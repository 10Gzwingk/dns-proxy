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
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Main {
    private static ServerBootstrap serverBootstrap = new ServerBootstrap();
    private static Bootstrap bootstrap = new Bootstrap();
    private static EventLoopGroup eventLoopGroup = new NioEventLoopGroup(1);
    private static Channel proxyDNS = null;
    private static int queryId = 0;
    private static Map<String, Answer> A = new HashMap<>();
    private static Map<String, Answer> CNAME = new HashMap<>();
    public static void main(String[] args) throws InterruptedException {
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

                                int count = dns.count(DnsSection.ANSWER);
                                List<DnsRecord> records = new ArrayList<>();
                                for (int i = 0; i < count; i++) records.add(dns.recordAt(DnsSection.ANSWER, i));
                                records.stream()
                                        .filter(r -> r.type().equals(DnsRecordType.A))
                                        .map(Record::new)
                                        .collect(Collectors.groupingBy(Record::name))
                                        .forEach((k, v) -> update(A, k, v));
                                records.stream()
                                        .filter(r -> r.type().equals(DnsRecordType.CNAME))
                                        .map(Record::new)
                                        .collect(Collectors.groupingBy(Record::name))
                                        .forEach((k, v) -> update(CNAME, k, v));

                                Channel channel = ctx.channel().attr(AttributeKey.<Channel>valueOf("channel")).get();
                                if (channel != null) {
                                    channel.writeAndFlush(dns);
                                    channel.close();
                                }
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                                super.exceptionCaught(ctx, cause);
                            }
                        });
                    }
                });
        new Thread(() -> {
            while (true){
                try {
                    Thread.sleep(30 * 1000L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                A.values().forEach(answer -> answer.records.removeIf(r -> Duration.between(LocalDateTime.now(), r.expire).getSeconds() <= 0));
                AtomicInteger i = new AtomicInteger(0);
                DefaultDnsQuery query = new DefaultDnsQuery(1);
                A.entrySet().stream()
                        .filter(entry -> entry.getValue().records.stream().anyMatch(r -> Duration.between(LocalDateTime.now(), r.expire).getSeconds() <= 30))
                        .forEach(entry -> query.addRecord(DnsSection.QUESTION, i.getAndIncrement(), entry.getValue().questionRecord.duplicate()));
                if (i.intValue() == 0) {
                    continue;
                }
                query.setOpCode(DnsOpCode.QUERY);
                query.setRecursionDesired(true);
                bootstrap.connect("8.8.8.8", 53)
                        .addListener((ChannelFutureListener) future -> {
                            if (!future.isSuccess()) {
                                return;
                            }
                            future.channel().writeAndFlush(query);
                        });

            }
        }).start();
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
                                if (DnsRecordType.A.equals(record.type()) && dnsQuery.isRecursionDesired() && A.containsKey(record.name())) {
                                    DefaultDnsResponse response = new DefaultDnsResponse(dnsQuery.id());
                                    response.setRecord(DnsSection.QUESTION, record);
                                    A.get(record.name()).records.stream()
                                            .filter(r -> r.expire.isAfter(LocalDateTime.now()))
                                            .map(r -> new DefaultDnsRawRecord(
                                                    r.record.name(),
                                                    r.record.type(),
                                                    Duration.between(LocalDateTime.now(), r.expire).getSeconds(),
                                                    r.record.content().copy())
                                            )
                                            .forEach(r -> response.addRecord(DnsSection.ANSWER, r));
                                    ctx.channel().writeAndFlush(response);
                                    return;
                                }

                                DefaultDnsQuery defaultDnsQuery = new DefaultDnsQuery(dnsQuery.id());
                                defaultDnsQuery.setOpCode(dnsQuery.opCode());
                                defaultDnsQuery.setRecord(DnsSection.QUESTION, dnsQuery.recordAt(DnsSection.QUESTION));
                                defaultDnsQuery.setRecursionDesired(dnsQuery.isRecursionDesired());
                                defaultDnsQuery.setZ(dnsQuery.z());
                                ChannelFuture proxy = bootstrap.connect("8.8.8.8", 53);
                                proxy.addListener(new ChannelFutureListener() {
                                    @Override
                                    public void operationComplete(ChannelFuture channelFuture) throws Exception {
                                        if (!channelFuture.isSuccess()) {
                                            channelFuture.channel().close();
                                            ctx.channel().close();
                                        }
                                        Channel proxy = channelFuture.channel();
                                        proxy.writeAndFlush(defaultDnsQuery);
                                        proxy.attr(AttributeKey.valueOf("channel")).set(ctx.channel());
                                    }
                                });
                            }
                        });
                    }
                })
                .bind("0.0.0.0", 5353)
                .sync();
    }

    static DnsResponse query(DnsQuery query) {
        int count = query.count(DnsSection.QUESTION);
        List<DnsQuery> queries = new ArrayList<>();
        for (int i = 0; i < count; i++) queries.add(query.recordAt(DnsSection.QUESTION, i));
        while (queries.size() > 0) {
            
        }
    }

    static void update(Map<String, Answer> map, String key, List<Record> records) {
        Answer answer = map.get(key);
        if (answer == null) {
            answer = new Answer();
            answer.lastAccess = LocalDateTime.now();
        }
        answer.records = records;
        map.put(key, answer);
    }

    static class Answer {
        List<Record> records = new ArrayList<>();
        DefaultDnsRawRecord questionRecord;
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
