package ink.accelerator.dns;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.dns.*;
import io.netty.util.AttributeKey;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class Main {
    private static ServerBootstrap serverBootstrap = new ServerBootstrap();
    private static Bootstrap bootstrap = new Bootstrap();
    private static EventLoopGroup eventLoopGroup = new NioEventLoopGroup(1);
    private static Channel proxyDNS = null;
    private static int queryId = 0;
    private static Map<String, Answer> A = new HashMap<>();
    private static String proxyIp;
    public static void main(String[] args) throws InterruptedException {
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

                                if (count > 0) {
                                    List<DnsRecord> records = new ArrayList<>();
                                    for (int i = 0; i < count; i++) records.add(dns.recordAt(DnsSection.ANSWER, i));

                                    List<Record> cacheRecords = records.stream().map(Record::new).collect(Collectors.toList());
                                    Answer answer = new Answer();
                                    answer.question = ctx.channel().attr(AttributeKey.<DefaultDnsQuestion>valueOf("question")).get();
                                    answer.records = cacheRecords;
                                    answer.lastAccess = LocalDateTime.now();
                                    A.put(name, answer);
                                }

                                Channel channel = ctx.channel().attr(AttributeKey.<Channel>valueOf("channel")).get();
                                if (channel != null) {
                                    Integer id = ctx.channel().attr(AttributeKey.<Integer>valueOf("id")).get();
                                    channel.writeAndFlush(getResponse(id, name));
                                    channel.close();
                                }
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                                Channel channel = ctx.channel().attr(AttributeKey.<Channel>valueOf("channel")).get();
                                if (channel != null) {
                                    Integer id = ctx.channel().attr(AttributeKey.<Integer>valueOf("id")).get();
                                    channel.writeAndFlush(new DefaultDnsResponse(id));
                                    channel.close();
                                }
                                super.exceptionCaught(ctx, cause);
                            }
                        });
                    }
                });

        eventLoopGroup.scheduleAtFixedRate(() -> {
            List<String> keys = A.entrySet().stream().filter(
                    e -> e.getValue().records.stream().anyMatch(r -> LocalDateTime.now().isAfter(r.expire.minusSeconds(10)))
            ).map(Map.Entry::getKey).collect(Collectors.toList());
            keys.forEach(key -> queryProxy(queryId++, new DefaultDnsQuestion(key, DnsRecordType.A), 0, null));
        }, 0, 10, TimeUnit.SECONDS);

        serverBootstrap.group(eventLoopGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel nioSocketChannel) throws Exception {
                        nioSocketChannel.pipeline().addLast(new TcpDnsQueryDecoder());
                        nioSocketChannel.pipeline().addLast(new TcpDnsResponseEncoder());
                        nioSocketChannel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                if (!(msg instanceof DnsQuery)) {
                                    return;
                                }
                                DnsQuery dnsQuery = (DnsQuery) msg;
                                DnsRecord record = dnsQuery.recordAt(DnsSection.QUESTION);
                                if (!DnsRecordType.A.equals(record.type()) || !dnsQuery.isRecursionDesired()) {
                                    ctx.channel().writeAndFlush(new DefaultDnsResponse(dnsQuery.id()));
                                    return;
                                }

                                if (A.containsKey(record.name())) {
                                    List<Record> records = A.get(record.name()).records;
                                    if (records.stream().anyMatch(r -> LocalDateTime.now().isAfter(r.expire))) {
                                        A.remove(record.name());
                                    } else {
                                        ctx.channel().writeAndFlush(getResponse(dnsQuery.id(), record.name()));
                                        return;
                                    }
                                }

                                queryProxy(dnsQuery.id(), dnsQuery.recordAt(DnsSection.QUESTION), dnsQuery.z(), ctx.channel());
                            }
                        });
                    }
                })
                .bind(args[1], Integer.parseInt(args[2]))
                .sync();
    }

    static void queryProxy(int id, DnsQuestion question, int z, Channel channel) {
        DefaultDnsQuery defaultDnsQuery = new DefaultDnsQuery(id);
        defaultDnsQuery.setOpCode(DnsOpCode.QUERY);
        defaultDnsQuery.setRecord(DnsSection.QUESTION, question);
        defaultDnsQuery.setRecursionDesired(true);
        defaultDnsQuery.setZ(z);
        ChannelFuture proxy = bootstrap.connect( proxyIp, 53);
        proxy.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture channelFuture) throws Exception {
                if (!channelFuture.isSuccess()) {
                    channelFuture.channel().close();
                    if (channel != null) {
                        channel.close();
                    }
                }
                Channel proxy = channelFuture.channel();
                if (channel != null) {
                    proxy.attr(AttributeKey.valueOf("channel")).set(channel);
                }
                proxy.attr(AttributeKey.valueOf("question")).set(question);
                proxy.attr(AttributeKey.valueOf("name")).set(question.name());
                proxy.attr(AttributeKey.valueOf("id")).set(id);
                proxy.writeAndFlush(defaultDnsQuery);
            }
        });
    }

    static DnsResponse getResponse(int id, String name) {
        if (!A.containsKey(name)) {
            return new DefaultDnsResponse(id);
        }
        Answer answer = A.get(name);
        answer.lastAccess = LocalDateTime.now();
        DefaultDnsResponse response = new DefaultDnsResponse(id);
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
}
