package ink.accelerator.dns;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.dns.*;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class Main {
    private static Bootstrap serverBootstrap = new Bootstrap();
    private static Bootstrap bootstrap = new Bootstrap();
    private static ServerBootstrap managerBootStrap = new ServerBootstrap();
    private static EventLoopGroup eventLoopGroup = new NioEventLoopGroup(1);
    private static Channel proxyDNS = null;
    private static int queryId = 0;
    private static Map<String, Answer> A = new HashMap<>();
    private static String proxyIp;

    private static String nonProxyIp = "211.140.188.188";

    private static Set<String> proxyDomains = new HashSet<>();
    static {
        proxyDomains.add(".");
    }

    private static boolean enableCache = false;

    public static void main(String[] args) throws InterruptedException {
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
                        nioSocketChannel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                if (!(msg instanceof DnsResponse)) {
                                    return;
                                }
                                DnsResponse dns = (DnsResponse) msg;
                                String name = ctx.channel().attr(AttributeKey.<String>valueOf("name")).get();

                                int count = dns.count(DnsSection.ANSWER);

                                if (count <= 0) {
                                    return;
                                }
                                List<DnsRecord> records = new ArrayList<>();
                                for (int i = 0; i < count; i++) records.add(dns.recordAt(DnsSection.ANSWER, i));

                                List<Record> cacheRecords = records.stream().map(Record::new).collect(Collectors.toList());
                                Channel channel = ctx.channel().attr(AttributeKey.<Channel>valueOf("channel")).get();
                                if (channel == null) {
                                    return;
                                }
                                Integer id = ctx.channel().attr(AttributeKey.<Integer>valueOf("id")).get();
                                DnsResponse response = getResponse(
                                        ctx.channel().attr(AttributeKey.<InetSocketAddress>valueOf("recipient")).get(),
                                        ctx.channel().attr(AttributeKey.<InetSocketAddress>valueOf("sender")).get(),
                                        id, name
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
                        });
                    }
                });

        eventLoopGroup.scheduleAtFixedRate(() -> {
            Set<String> expiredKeys = A.entrySet().stream()
                    .filter(entry -> entry.getValue().lastAccess.isBefore(LocalDateTime.now().minusHours(1)))
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());
            System.out.println("expiredKeys size=" + expiredKeys.size());
            (new HashSet<>(expiredKeys)).forEach(key -> A.remove(key));


            try {
                List<String> keys = A.entrySet().stream()
                        .filter(e -> e.getValue().records.stream().anyMatch(r -> LocalDateTime.now().isAfter(r.expire.minusSeconds(10))))
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toList());
                System.out.println("refresh keys size=" + keys.size());
                keys.forEach(key -> queryProxy(queryId++, new DefaultDnsQuestion(key, DnsRecordType.A), null, null));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, 0, 10, TimeUnit.SECONDS);

        managerBootStrap.group(eventLoopGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel ch) throws Exception {
                        ch.pipeline().addLast(new StringEncoder());
                        ch.pipeline().addLast(new StringDecoder());
                        ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                ctx.writeAndFlush(executeCommand((String) msg) + "\n");
                            }
                        });
                    }
                })
                .bind("0.0.0.0", 5355);

        serverBootstrap.group(eventLoopGroup)
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
                .sync();
        Thread.sleep(3600 * 24 * 365 * 1000L);
    }

    static String executeCommand(String command) {
        StringBuilder sb = new StringBuilder();
        switch (command) {
            case "count\n":
                return String.valueOf(A.size());
            case "list\n":
                A.keySet().forEach(key -> sb.append(key).append("\n"));
                return sb.toString();
            case "listproxy\n":
                proxyDomains.forEach(key -> sb.append(key).append("\n"));
                return sb.toString();
            default:
                if (command.startsWith("proxy")) {
                    proxyIp = command.split(" ")[1];
                    return proxyIp;
                }
                if (command.startsWith("remove")) {
                    A.remove(command.substring(7));
                }
                if (command.startsWith("addproxy")) {
                    String domain = command.split(" ")[1];
                    proxyDomains.add(domain.substring(0, domain.length() - 1));
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
        DefaultDnsQuery defaultDnsQuery = new DefaultDnsQuery(id);
        defaultDnsQuery.setOpCode(DnsOpCode.QUERY);
        defaultDnsQuery.setRecord(DnsSection.QUESTION, question);
        defaultDnsQuery.setRecursionDesired(true);
        ChannelFuture proxy = bootstrap.connect( doProxy ? proxyIp : nonProxyIp, 53);
        proxy.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture channelFuture) throws Exception {
                if (!channelFuture.isSuccess()) {
                    channelFuture.channel().close();
                }
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
    }

    static DnsResponse getResponse(InetSocketAddress src, InetSocketAddress dst, int id, String name) {
        if (!A.containsKey(name)) {
            return new DatagramDnsResponse(src, dst, id);
        }
        Answer answer = A.get(name);
        answer.lastAccess = LocalDateTime.now();
        DefaultDnsResponse response = new DatagramDnsResponse(src, dst, id);
        response.setRecord(DnsSection.QUESTION, answer.question);
        answer.records.stream()
                .map(r -> new DefaultDnsRawRecord(
                        r.record.name(),
                        r.record.type(),
                        Duration.between(LocalDateTime.now(), r.expire).getSeconds(),
                        r.record.content().copy())
                )
                .forEach(r -> response.addRecord(DnsSection.ANSWER, r));
        return response;
    }

    static DnsResponse getResponse(InetSocketAddress src, InetSocketAddress dst, int id, Answer answer) {
        answer.lastAccess = LocalDateTime.now();
        DefaultDnsResponse response = new DatagramDnsResponse(src, dst, id);
        response.setRecord(DnsSection.QUESTION, answer.question);
        answer.records.stream()
                .map(r -> new DefaultDnsRawRecord(
                        r.record.name(),
                        r.record.type(),
                        Duration.between(LocalDateTime.now(), r.expire).getSeconds(),
                        r.record.content().copy())
                )
                .forEach(r -> response.addRecord(DnsSection.ANSWER, r));
        return response;
    }

    static class Answer {
        List<Record> records = new ArrayList<>();
        DefaultDnsQuestion question;
        LocalDateTime lastAccess;
    }

    static class Record {
        DefaultDnsRawRecord record;
        LocalDateTime expire;

        public Record(DnsRecord record) {
            this.record = (DefaultDnsRawRecord) ((DefaultDnsRawRecord) record).duplicate();
            this.expire = LocalDateTime.now().plusSeconds(record.timeToLive());
        }

        String name() {
            return record.name();
        }
    }

    static void put(String key, Answer answer) {
        if (enableCache) {
            A.put(key, answer);
        }
    }

    static Answer get(String key) {
        if (!enableCache) return null;
        Answer answer = A.get(key);
        List<Record> records = answer.records;
        if (records.stream().anyMatch(r -> LocalDateTime.now().isAfter(r.expire))) {
            A.remove(key);
            return null;
        }
        return answer;
    }
}
