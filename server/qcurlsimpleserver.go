package main
import(
	"sync"
	"fmt"
	"github.com/q191201771/lal/pkg/rtmp"
	"github.com/q191201771/lal/pkg/logic"
	"github.com/q191201771/lal/pkg/base"
	//"github.com/q191201771/naza/pkg/nazalog"
	//quic "github.com/lucas-clemente/quic-go"
)
type pushProxy struct {
	isPushing   bool
	pushSession *rtmp.PushSession
}
type pullProxy struct {
	isPulling   bool
	pullSession *rtmp.PullSession
}


type ServerManager struct {

	rtmpServer    *rtmp.Server
	exitChan      chan struct{}

	mutex    sync.Mutex
	groupMap map[string]*logic.Group // TODO chef: with appName
}


func main(){
	var (
		rtmpserver *rtmp.Server
		addr string
	)
	conffile := "lalserver.conf.json"
	addr = "0.0.0.0:1935"
	logic.Init(conffile)
	m := &ServerManager{
		groupMap: make(map[string]*logic.Group),
		exitChan: make(chan struct{}),
	}
	rtmpserver = rtmp.NewServer(m,addr)
	// if err := rtmpserver.Listen(); err != nil {
	// 	return err
	// }
	rtmpserver.Listen()
	// go func() {
	// 	if err := rtmpserver.RunLoop(); err != nil {
	// 		nazalog.Error(err)
	// 	}
	// }()
	rtmpserver.RunLoop()

	rtmpserver.Listen()

	rtmpserver.RunLoop()
}

// ServerObserver of rtmp.Server
func (sm *ServerManager) OnRTMPConnect(session *rtmp.ServerSession, opa rtmp.ObjectPairArray) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	var info base.RTMPConnectInfo
	info.ServerID ="111"
	info.SessionID = session.UniqueKey()
	//info.RemoteAddr = session.GetStat().RemoteAddr
	if app, err := opa.FindString("app"); err == nil {
		info.App = app
	}
	if flashVer, err := opa.FindString("flashVer"); err == nil {
		info.FlashVer = flashVer
	}
	if tcURL, err := opa.FindString("tcUrl"); err == nil {
		info.TCURL = tcURL
	}
	logic.HttpNotify.OnRTMPConnect(info)
}

func (sm *ServerManager) getGroup(appName string, streamName string) *logic.Group {
	group, exist := sm.groupMap[streamName]
	if !exist {
		return nil
	}
	return group
}

// ServerObserver of rtmp.Server
func (sm *ServerManager) OnDelRTMPPubSession(session *rtmp.ServerSession) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	group := sm.getGroup(session.AppName(), session.StreamName())
	if group == nil {
		return
	}

	group.DelRTMPPubSession(session)

	var info base.PubStopInfo
	//info.ServerID = config.ServerID
	info.ServerID = "111"
	info.Protocol = base.ProtocolRTMP
	info.URL = session.URL()
	info.AppName = session.AppName()
	info.StreamName = session.StreamName()
	info.URLParam = session.RawQuery()
	info.SessionID = session.UniqueKey()
	//info.RemoteAddr = session.GetStat().RemoteAddr
	info.HasInSession = group.HasInSession()
	info.HasOutSession = group.HasOutSession()
	logic.HttpNotify.OnPubStop(info)
}

// ServerObserver of rtmp.Server
func (sm *ServerManager) OnNewRTMPSubSession(session *rtmp.ServerSession) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	group := sm.getOrCreateGroup(session.AppName(), session.StreamName())
	group.AddRTMPSubSession(session)

	var info base.SubStartInfo
	info.ServerID = "111"
	info.Protocol = base.ProtocolRTMP
	info.Protocol = session.URL()
	info.AppName = session.AppName()
	info.StreamName = session.StreamName()
	info.URLParam = session.RawQuery()
	info.SessionID = session.UniqueKey()
	//info.RemoteAddr = session.GetStat().RemoteAddr
	info.HasInSession = group.HasInSession()
	info.HasOutSession = group.HasOutSession()
	logic.HttpNotify.OnSubStart(info)

	return true
}

func (sm *ServerManager) OnNewRTMPPubSession(session *rtmp.ServerSession) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	group := sm.getOrCreateGroup(session.AppName(), session.StreamName())
	res := group.AddRTMPPubSession(session)

	// TODO chef: res值为false时，可以考虑不回调
	// TODO chef: 每次赋值都逐个拼，代码冗余，考虑直接用ISession抽离一下代码
	var info base.PubStartInfo
	info.ServerID ="111"
	info.Protocol = base.ProtocolRTMP
	info.URL = session.URL()
	info.AppName = session.AppName()
	info.StreamName = session.StreamName()
	info.URLParam = session.RawQuery()
	info.SessionID = session.UniqueKey()
	//info.RemoteAddr = session.GetStat().RemoteAddr
	info.HasInSession = group.HasInSession()
	info.HasOutSession = group.HasOutSession()
	logic.HttpNotify.OnPubStart(info)
	return res
}


// ServerObserver of rtmp.Server
func (sm *ServerManager) OnDelRTMPSubSession(session *rtmp.ServerSession) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	group := sm.getGroup(session.AppName(), session.StreamName())
	if group == nil {
		return
	}

	group.DelRTMPSubSession(session)

	var info base.SubStopInfo
	info.ServerID = "111"
	info.Protocol = base.ProtocolRTMP
	info.AppName = session.AppName()
	info.StreamName = session.StreamName()
	info.URLParam = session.RawQuery()
	info.SessionID = session.UniqueKey()
	//info.RemoteAddr = session.GetStat().RemoteAddr
	info.HasInSession = group.HasInSession()
	info.HasOutSession = group.HasOutSession()
	logic.HttpNotify.OnSubStop(info)
}


func (sm *ServerManager) getOrCreateGroup(appName string, streamName string) *logic.Group {
	group, exist := sm.groupMap[streamName]
	if !exist {
		// pullURL := fmt.Sprintf("rtmp://%s/%s/%s", config.RelayPullConfig.Addr, appName, streamName)
		// group = logic.NewGroup(appName, streamName, config.RelayPullConfig.Enable, pullURL)
		pullURL := fmt.Sprintf("rtmp://%s/%s/%s", "", appName, streamName)
		group = logic.NewGroup(appName, streamName, false, pullURL)
		sm.groupMap[streamName] = group

		go group.RunLoop()
	}
	return group
}