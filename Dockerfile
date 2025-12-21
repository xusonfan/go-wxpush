# 第一阶段：使用 Alpine 获取时区数据库
FROM alpine:latest AS builder
RUN apk --no-cache add tzdata

# 第二阶段：使用 scratch 作为最终镜像
FROM scratch

WORKDIR $GOPATH/src/github.com/hezhizheng/go-wxpush

# 复制时区数据库文件
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

COPY . $GOPATH/src/github.com/hezhizheng/go-wxpush

ENTRYPOINT ["./go-wxpush_linux_amd64"]
 # 默认参数
CMD ["-port", "5566", "-appid", "","-secret","","-userid","","-template_id","","-base_url","https://push.hzz.cool/detail","-title","","-content","","-tz",""]