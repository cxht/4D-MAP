# 3D-MAP
Live streaming framework based on RTMP over MPQUIC
## Component
* Pusher: main.go
* Server: server/
* Puller: ffplay

## Usage
First run the server, then the puller, at last the pusher.
1. Download go v1.17
2. Download this project
3. Copy the quic-go43DMAP to go/src/github.com/lucas-clement/, Copy the lal-43DMAP to go/src/github.com/

```sh
As a server
  cd 3D-MAP/server
  go run server.go -protocol=[quic/tcp] -au=[true/false]

As a puller:
  ffplay rtmp://x.x.x.x

As a pusher:
  cd 3D-MAP/
  go build
  ./3D-MAP -type=false -file=video_dir -protocol=[quic/tcp] =multi=true -sch=[rtt/stms/dispatch/RDDT/duplicate] -network=[udp4/tcp] -red=false -iprio=[true/false] rtmp://x.x.x.x 
