// Copyright 2021, Chef.  All rights reserved.
// https://github.com/q191201771/lal
//
// Use of this source code is governed by a MIT-style license
// that can be found in the License file.
//
// Author: Chef (191201771@qq.com)

package base

import (
	"testing"
)

func TestHTTPServerManager(t *testing.T) {
	//var err error
	//
	//var fnFLV = func(writer http.ResponseWriter, request *http.Request) {
	//	nazalog.Debugf("> fnFLV. %+v, %+v", writer, request)
	//	conn, bio, err := writer.(http.Hijacker).Hijack()
	//	if err != nil {
	//		nazalog.Errorf("hijack failed. err=%+v", err)
	//		return
	//	}
	//	if bio.Reader.Buffered() != 0 || bio.Writer.Buffered() != 0 {
	//		nazalog.Errorf("hijack but buffer not empty. rb=%d, wb=%d", bio.Reader.Buffered(), bio.Writer.Buffered())
	//	}
	//	nazalog.Debugf("%+v, %+v, %+v", conn, bio, err)
	//}
	//
	//sm := NewHTTPServerManager()
	//
	//err = sm.AddListen(
	//	LocalAddrCtx{IsHTTPS: false, Addr: ":8080"},
	//	"/live/",
	//	fnFLV,
	//)
	//assert.Equal(t, nil, err)
	//
	//err = sm.AddListen(
	//	LocalAddrCtx{IsHTTPS: true, Addr: ":4433", CertFile: "../../conf/cert.pem", KeyFile: "../../conf/key.pem"},
	//	"/live/",
	//	fnFLV,
	//)
	//assert.Equal(t, nil, err)
	//
	//err = sm.RunLoop()
	//assert.Equal(t, nil, err)
}
