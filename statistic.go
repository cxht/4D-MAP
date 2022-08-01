package main
import(
	"time"
	//"github.com/q191201771/naza/pkg/nazalog"
)
type QOEstat struct {

	FPS float64 `json:"FPS"`
}
func (state *QOEstat)GetFPS(){
	for{
		//nazalog.Debugf("FPS: %v", state.FPS)
		time.Sleep(time.Second)
	}
}

func (state *QOEstat)UpdateFPS(time float64){
	state.FPS = 10/time
}
