package main

// 落地页硬验收：预览元数据正确服务、仅文字无图像、作品名列表（顺序/占位/转义/降级）、
// 深链、免责声明占位、元数据转义（防注入）、状态展示、举报入口。

import (
	"strings"
	"testing"
)

// TestLandingPageServesTextMetadataOnly 落地页仅展示文字元数据，不含任何图像；
// 预留候选地址字段（V2 直连位）经注册登记、管理端可见
func TestLandingPageServesTextMetadataOnly(t *testing.T) {
	const adminToken = "test-admin-token"
	h := startRelay(t, func(c *Config) {
		c.DownloadURL = "https://example.com/download"
		c.AdminToken = adminToken
	})
	candidates := []string{"[2001:db8::1]:9527", "203.0.113.7:9527"}
	A := startSharer(t, h.addr, regOpts{
		meta:           &shareMeta{Title: "我的收藏夹", WorkCount: 12, Source: "pixiv"},
		candidateAddrs: candidates,
	})

	code, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	if code != 200 {
		t.Fatalf("落地页状态码 %d", code)
	}
	for _, want := range []string{"我的收藏夹", "12", "pixiv", A.token, "library-squirrel://share/", "举报", "打开应用", "https://example.com/download"} {
		if !strings.Contains(body, want) {
			t.Errorf("落地页缺少 %q", want)
		}
	}
	// 预览最小化：不展示任何图像
	if strings.Contains(strings.ToLower(body), "<img") || strings.Contains(strings.ToLower(body), "background-image") {
		t.Error("落地页包含图像元素——违反预览最小化约束")
	}
	// 免责声明占位存在
	if !strings.Contains(body, `id="disclaimer"`) {
		t.Error("落地页缺少免责声明占位")
	}
	// 预留候选地址字段已登记（协议本期不消费，管理端可见）
	_, adminBody := httpGetWithToken(t, "http://"+h.addr+"/admin/sessions", adminToken)
	if !strings.Contains(adminBody, "[2001:db8::1]:9527") {
		t.Errorf("管理端会话清单缺少预留候选地址: %s", adminBody)
	}
}

// TestLandingPageEscapesMetadata 元数据经模板转义，标题注入不产生可执行标记
func TestLandingPageEscapesMetadata(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{
		meta: &shareMeta{Title: `<script>alert("xss")</script>`, WorkCount: 1, Source: "pixiv<img src=x>"},
	})
	_, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	// 页面自身的 <script> 块属模板固定内容；注入判定只看标题原文是否以可执行形态出现
	if strings.Contains(body, `<script>alert`) {
		t.Error("标题未转义，存在注入风险")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("转义后的标题未出现在页面中")
	}
	if strings.Contains(body, `<img src=x`) {
		t.Error("来源字段未转义")
	}
}

// TestLandingPageWorksNameList 设计十：register 帧 meta 携带 worksName，落地页按序渲染作品名列表。
// 顺序对齐传入数组；空名占位「作品 {ID}」由分享方填充、中继原样展示；超长截断走 CSS ellipsis
// （与标题一致先经 200 字符校验上限）；html/template 转义防注入且预览最小化不被破坏。
func TestLandingPageWorksNameList(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{
		meta: &shareMeta{
			Title:     "作品名分享",
			WorkCount: 3,
			Source:    "pixiv",
			WorksName: []string{"作品 1", "第二幅", "<img src=x onerror=alert(1)>"},
		},
	})

	_, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)

	// 列表区块、有序列表与截断样式存在
	for _, want := range []string{"作品列表", `class="works-list"`, "text-overflow:ellipsis"} {
		if !strings.Contains(body, want) {
			t.Errorf("落地页缺少 %q", want)
		}
	}
	// 顺序对齐：作品名按传入顺序依次出现（空名占位「作品 {ID}」是分享方填充文本，中继原样透传）
	pos := -1
	for _, name := range []string{"作品 1", "第二幅"} {
		idx := strings.Index(body, name)
		if idx < 0 {
			t.Fatalf("落地页缺少作品名 %q", name)
		}
		if idx <= pos {
			t.Fatalf("作品名 %q 顺序错乱（前一名位置 %d，本名位置 %d）", name, pos, idx)
		}
		pos = idx
	}
	// 注入名被转义，不产生可执行标记；预览最小化仍成立（无任何 <img）
	if strings.Contains(strings.ToLower(body), "<img") {
		t.Error("落地页包含未转义 <img——注入风险或违反预览最小化")
	}
	if !strings.Contains(body, "&lt;img") {
		t.Error("作品名注入未转义")
	}
}

// TestLandingPageWorksNameGracefulDegradation 无 worksName（旧分享方/空分享，键不出现）时
// 落地页不渲染作品名列表区、不报错——优雅降级。
func TestLandingPageWorksNameGracefulDegradation(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{
		meta: &shareMeta{Title: "无作品名", WorkCount: 3, Source: "pixiv"},
	})
	code, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	if code != 200 {
		t.Fatalf("落地页状态码 %d", code)
	}
	if strings.Contains(body, "作品列表") {
		t.Error("无 worksName 时不应渲染作品名列表区")
	}
}

// TestValidateShareMetaWorksName 设计十：worksName 校验——单名超长/含控制字符/条数超限拒绝，合法通过
// （单名上限与标题一致 200 字符；条数上限为防御极端载荷，实际还受 HELLO 帧 maxHelloBytes 约束）
func TestValidateShareMetaWorksName(t *testing.T) {
	cases := []struct {
		name string
		meta *shareMeta
		want bool // true=应拒绝
	}{
		{"合法", &shareMeta{WorksName: []string{"作品 1", "第二幅"}}, false},
		{"单名超长", &shareMeta{WorksName: []string{strings.Repeat("名", maxWorksNameLen+1)}}, true},
		{"单名控制字符", &shareMeta{WorksName: []string{"作品\n1"}}, true},
		{"条数超限", &shareMeta{WorksName: make([]string, maxWorksNameCount+1)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateShareMeta(tc.meta)
			if tc.want && err == nil {
				t.Fatal("应拒绝但通过")
			}
			if !tc.want && err != nil {
				t.Fatalf("应通过但拒绝: %v", err)
			}
		})
	}
}

// TestLandingPageStates 落地页状态：未知 token 404；撤销后展示已失效
func TestLandingPageStates(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{})

	if code, _ := httpGet(t, "http://"+h.addr+"/s/AAAAAAAAAAAAAAAAAAAAAA"); code != 404 {
		t.Fatalf("未知 token 应 404，得到 %d", code)
	}
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A.token+"/report", "", nil); code != 200 {
		t.Fatalf("举报失败: %d", code)
	}
	_, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	if !strings.Contains(body, "已被撤销") {
		t.Fatalf("撤销后落地页未展示失效状态: %s", body)
	}
	// 举报入口限流：默认每 IP 每小时 10 次，测试下调后验证 429
}

// TestReportRateLimit 举报入口限流
func TestReportRateLimit(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.ReportPerIPPerHour = 2 })
	A := startSharer(t, h.addr, regOpts{})
	for i := 0; i < 2; i++ {
		if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A.token+"/report", "", nil); code != 200 {
			t.Fatalf("限流内举报失败: %d", code)
		}
	}
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A.token+"/report", "", nil); code != 429 {
		t.Fatalf("举报限流应 429，得到 %d", code)
	}
}

// TestHealthz 健康检查端点
func TestHealthz(t *testing.T) {
	h := startRelay(t, nil)
	code, body := httpGet(t, "http://"+h.addr+"/healthz")
	if code != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("healthz 异常: %d %s", code, body)
	}
}
