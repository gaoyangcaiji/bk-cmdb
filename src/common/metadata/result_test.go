package metadata

import (
	"testing"

	"configcenter/src/common/errors"
)

func TestResponse(t *testing.T) {

	err := errors.New(9999999, "test-msg")

	respPtr := &Response{
		BaseResp: BaseResp{
			Result: false,
			Code:   err.GetCode(),
			ErrMsg: err.Error(),
		},
	}

	ccErr := respPtr.CCError()
	if ccErr == nil {
		t.Errorf("not error")
		return
	}

	if err.GetCode() != ccErr.GetCode() ||
		err.Error() != ccErr.Error() {
		t.Errorf("code info, code:%v, error msg:%s", ccErr.GetCode(), ccErr.Error())
		return
	}

	resp := Response{
		BaseResp: BaseResp{
			Result: false,
			Code:   err.GetCode(),
			ErrMsg: err.Error(),
		},
	}

	ccErr = resp.CCError()
	if ccErr == nil {
		t.Errorf("not error")
		return
	}

	if err.GetCode() != ccErr.GetCode() ||
		err.Error() != ccErr.Error() {
		t.Errorf("code info, code:%v, error msg:%s", ccErr.GetCode(), ccErr.Error())
		return
	}

	respSucc := Response{
		BaseResp: BaseResp{
			Result: true,
			Code:   0,
			ErrMsg: "",
		},
	}
	ccErr = respSucc.CCError()
	if ccErr != nil {
		t.Errorf("have error")
		return
	}

}
