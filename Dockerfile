FROM golang:1.17 as builder
ADD . /src/alisg
WORKDIR /src/alisg 
RUN make docker-in

# FROM scratch
FROM alpine
LABEL desc="用于在安全组添加 ip"
COPY --from=builder /src/alisg/bin/alisg /alisg
EXPOSE 5000
ENTRYPOINT ["/alisg"]
