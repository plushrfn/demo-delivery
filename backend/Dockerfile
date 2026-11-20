FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY page.html ./
RUN CGO_ENABLED=0 go build -o /out/delivery .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/delivery /delivery
EXPOSE 8090
ENTRYPOINT ["/delivery"]
