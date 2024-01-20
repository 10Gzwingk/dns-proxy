package ink.accelerator.dns;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.dns.*;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

public class Main {
    private static final Bootstrap serverBootstrap = new Bootstrap();
    private static final Bootstrap bootstrap = new Bootstrap();
    private static final Bootstrap nonProxyBootstrap = new Bootstrap();
    private static final EventLoopGroup eventLoopGroup = new NioEventLoopGroup(1);
    private static String proxyIp = "8.8.8.8";
    private static String nonProxyIp = "211.140.188.188";
    private static final Set<String> proxyDomains = new HashSet<>();
    static {
        proxyDomains.add("google");
    }
    private static final Map<Integer, InetSocketAddress> socketMap = new HashMap<>();
    private static final Map<Integer, Integer> idMap = new HashMap<>();
    private static InetSocketAddress serverSocketAddress = null;
    private static Channel serverChannel = null;
    private static Channel clientNonProxyChannel;
    private static InetSocketAddress clientLocalSocketAddress;
    private static InetSocketAddress clientRemoteSocketAddress;
    private static int globalId = 0;

    public static void main(String[] args) throws InterruptedException, IOException {
        serverSocketAddress = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
        clientLocalSocketAddress = new InetSocketAddress(args[1], 54321);
        clientRemoteSocketAddress = new InetSocketAddress(nonProxyIp, 53);
        DatagramDnsQueryDecoder datagramDnsQueryDecoder = new DatagramDnsQueryDecoder();
        DatagramDnsResponseEncoder datagramDnsResponseEncoder = new DatagramDnsResponseEncoder();

        proxyIp = args[0];
        bootstrap.group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel nioSocketChannel) throws Exception {
                        nioSocketChannel.pipeline().addLast(new TcpDnsQueryEncoder());
                        nioSocketChannel.pipeline().addLast(new TcpDnsResponseDecoder());
                        nioSocketChannel.pipeline().addLast(dnsClientHandler);
                    }
                });
        // 透传客户端，走udp
        clientNonProxyChannel = nonProxyBootstrap.group(eventLoopGroup)
                .channel(NioDatagramChannel.class)
                .handler(new ChannelInitializer<NioDatagramChannel>() {
                    @Override
                    protected void initChannel(NioDatagramChannel channel) throws Exception {
                        channel.pipeline().addLast(new DatagramDnsQueryEncoder());
                        channel.pipeline().addLast(new DatagramDnsResponseDecoder());
                        channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                if (!(msg instanceof DnsResponse dns)) {
                                    return;
                                }
                                if (!socketMap.containsKey(dns.id())) {
                                    System.out.println("[error] client socket not exists");
                                    return;
                                }
                                int count = dns.count(DnsSection.ANSWER);
                                if (count <= 0) {
                                    return;
                                }
                                List<DnsRecord> records = new ArrayList<>();
                                for (int i = 0; i < count; i++) records.add(dns.recordAt(DnsSection.ANSWER, i));

                                List<Record> cacheRecords = records.stream().map(Record::new).toList();
                                DnsResponse response = new DatagramDnsResponse(serverSocketAddress, socketMap.get(dns.id()), idMap.get(dns.id()));
                                response.setRecord(DnsSection.QUESTION, dns.recordAt(DnsSection.QUESTION, 0));
                                cacheRecords.stream()
                                        .map(r -> new DefaultDnsRawRecord(
                                                r.record.name(),
                                                r.record.type(),
                                                Duration.between(LocalDateTime.now(), r.expire).getSeconds(),
                                                r.record.content().copy())
                                        )
                                        .forEach(r -> response.addRecord(DnsSection.ANSWER, r));
                                serverChannel.writeAndFlush(response);
                                dns.release();
                                idMap.remove(dns.id());
                                socketMap.remove(dns.id());
                            }
                        });
                    }
                })
                .bind(clientLocalSocketAddress)
                .sync()
                .channel();

        serverChannel = serverBootstrap.group(eventLoopGroup)
                .channel(NioDatagramChannel.class)
                .handler(new ChannelInitializer<NioDatagramChannel>() {
                    @Override
                    protected void initChannel(NioDatagramChannel nioSocketChannel) throws Exception {
                        nioSocketChannel.pipeline().addLast(datagramDnsQueryDecoder);
                        nioSocketChannel.pipeline().addLast(datagramDnsResponseEncoder);
                        nioSocketChannel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                try {
                                    if (!(msg instanceof DatagramDnsQuery dnsQuery)) {
                                        return;
                                    }

                                    // 获取请求参数
                                    DnsRecord record = dnsQuery.recordAt(DnsSection.QUESTION);
                                    if (!DnsRecordType.A.equals(record.type()) || !dnsQuery.isRecursionDesired()) {
                                        ctx.channel().writeAndFlush(new DefaultDnsResponse(dnsQuery.id()));
                                        return;
                                    }

                                    queryProxy(dnsQuery.id(), dnsQuery.recordAt(DnsSection.QUESTION), ctx.channel(), dnsQuery);
                                    dnsQuery.release();
                                } catch (Exception e) {
                                    System.out.println("channelRead: udp channel exception");
                                    e.printStackTrace();
                                }
                            }
                        });
                    }

                    @Override
                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                        System.out.println("exceptionCaught: udp channel exception");
                        cause.printStackTrace();
                    }
                })
                .bind(args[1], Integer.parseInt(args[2]))
                .sync()
                .channel();

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while (true) {
            line = bufferedReader.readLine();
            if (line == null) {
                continue;
            }
            System.out.println(executeCommand(line));
        }
    }

    static final ChannelHandler dnsClientHandler = new DnsClientHandler();

    @ChannelHandler.Sharable
    static class DnsClientHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (!(msg instanceof DnsResponse dns)) {
                return;
            }

            int count = dns.count(DnsSection.ANSWER);

            if (count <= 0) {
                return;
            }
            List<DnsRecord> records = new ArrayList<>();
            for (int i = 0; i < count; i++) records.add(dns.recordAt(DnsSection.ANSWER, i));

            List<Record> cacheRecords = records.stream().map(Record::new).toList();
            Channel channel = ctx.channel().attr(AttributeKey.<Channel>valueOf("channel")).get();
            if (channel == null) {
                return;
            }
            Integer id = ctx.channel().attr(AttributeKey.<Integer>valueOf("id")).get();
            DnsResponse response = new DatagramDnsResponse(
                    ctx.channel().attr(AttributeKey.<InetSocketAddress>valueOf("recipient")).get(),
                    ctx.channel().attr(AttributeKey.<InetSocketAddress>valueOf("sender")).get(),
                    id
            );
            response.setRecord(DnsSection.QUESTION, ctx.channel().attr(AttributeKey.<DefaultDnsQuestion>valueOf("question")).get());
            cacheRecords.stream()
                    .map(r -> new DefaultDnsRawRecord(
                            r.record.name(),
                            r.record.type(),
                            Duration.between(LocalDateTime.now(), r.expire).getSeconds(),
                            r.record.content().copy())
                    )
                    .forEach(r -> response.addRecord(DnsSection.ANSWER, r));
            channel.writeAndFlush(response);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            try {
                cause.printStackTrace();
                Channel channel = ctx.channel();
                if (channel == null) return;
                Attribute<Channel> attr = channel.attr(AttributeKey.<Channel>valueOf("channel"));
                if (attr == null) return;
                Channel pairChannel = attr.get();
                if (pairChannel == null) return;
                Attribute<Integer> idAttr = channel.attr(AttributeKey.<Integer>valueOf("id"));
                if (idAttr != null) {
                    pairChannel.writeAndFlush(new DefaultDnsResponse(idAttr.get()));
                }
                channel.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static String executeCommand(String command) {
        StringBuilder sb = new StringBuilder();
        switch (command) {
//            case "count\n":
//                return String.valueOf(A.size());
//            case "list\n":
//                A.keySet().forEach(key -> sb.append(key).append("\n"));
//                return sb.toString();
            case "listproxy":
                proxyDomains.forEach(key -> sb.append(key).append("\n"));
                return sb.toString();
            default:
                if (command.startsWith("proxy")) {
                    proxyIp = command.split(" ")[1];
                    return proxyIp;
                }
                if (command.startsWith("nonProxyIp")) {
                    nonProxyIp = command.split(" ")[1];
                    return nonProxyIp;
                }
//                if (command.startsWith("remove")) {
//                    A.remove(command.substring(7));
//                }
                if (command.startsWith("addproxy")) {
                    String domain = command.split(" ")[1];
                    proxyDomains.add(domain);
                }
                if (command.startsWith("delproxy")) {
                    String domain = command.split(" ")[1];
                    proxyDomains.remove(domain);
                }
                return "ok";
        }
    }

    static void queryProxy(int id, DnsQuestion question, Channel channel, DatagramDnsQuery query) {
        boolean doProxy = proxyDomains.stream()
                .anyMatch(domain -> question.name().contains(domain));
        ChannelFuture proxy;
        if (doProxy) {
            proxy = bootstrap.connect(proxyIp, 53);
            proxy.addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture channelFuture) throws Exception {
                    if (!channelFuture.isSuccess()) {
                        channelFuture.channel().close();
                    }
                    DefaultDnsQuery defaultDnsQuery = new DefaultDnsQuery(id);
                    defaultDnsQuery.setOpCode(DnsOpCode.QUERY);
                    defaultDnsQuery.setRecord(DnsSection.QUESTION, question);
                    defaultDnsQuery.setRecursionDesired(true);
                    Channel proxy = channelFuture.channel();
                    if (channel != null) {
                        proxy.attr(AttributeKey.valueOf("channel")).set(channel);
                    }
                    if (query != null) {
                        proxy.attr(AttributeKey.valueOf("sender")).set(query.sender());
                        proxy.attr(AttributeKey.valueOf("recipient")).set(query.recipient());
                    }
                    proxy.attr(AttributeKey.valueOf("question")).set(question);
                    proxy.attr(AttributeKey.valueOf("name")).set(question.name());
                    proxy.attr(AttributeKey.valueOf("id")).set(id);
                    proxy.writeAndFlush(defaultDnsQuery);
                }
            });
        } else {
            globalId = globalId + 1;
            DefaultDnsQuery defaultDnsQuery = new DatagramDnsQuery(clientLocalSocketAddress, clientRemoteSocketAddress, globalId);
            defaultDnsQuery.setOpCode(DnsOpCode.QUERY);
            defaultDnsQuery.setRecord(DnsSection.QUESTION, question);
            defaultDnsQuery.setRecursionDesired(true);
            socketMap.put(globalId, query.sender());
            idMap.put(globalId, id);
            clientNonProxyChannel.writeAndFlush(defaultDnsQuery);
        }
    }

    static class Record {
        DefaultDnsRawRecord record;
        LocalDateTime expire;

        public Record(DnsRecord record) {
            this.record = (DefaultDnsRawRecord) ((DefaultDnsRawRecord) record).duplicate();
            this.expire = LocalDateTime.now().plusSeconds(record.timeToLive());
        }
    }
}
