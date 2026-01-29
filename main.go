package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"
)

// 请求参数结构体
type RequestParams struct {
	Title      string `json:"title" form:"title"`
	Content    string `json:"content" form:"content"`
	AppID      string `json:"appid" form:"appid"`
	Secret     string `json:"secret" form:"secret"`
	UserID     string `json:"userid" form:"userid"`
	TemplateID string `json:"template_id" form:"template_id"`
	BaseURL    string `json:"base_url" form:"base_url"`
	Timezone   string `json:"tz" form:"tz"`
}

// 全局变量用于存储命令行参数
var (
	cliTitle      string
	cliContent    string
	cliAppID      string
	cliSecret     string
	cliUserID     string
	cliTemplateID string
	cliBaseURL    string
	startPort     string
	cliTimezone   string
)

// 微信AccessToken响应
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Errcode     int    `json:"errcode"`
	Errmsg      string `json:"errmsg"`
}

// TokenCache 缓存结构体
type TokenCache struct {
	AccessToken string
	ExpireTime  time.Time
	mu          sync.RWMutex
}

var tokenCacheMap = make(map[string]*TokenCache)
var cacheMu sync.Mutex

// 微信模板消息请求
type TemplateMessageRequest struct {
	ToUser     string                 `json:"touser"`
	TemplateID string                 `json:"template_id"`
	URL        string                 `json:"url"`
	Data       map[string]interface{} `json:"data"`
}

// 微信API响应
type WechatAPIResponse struct {
	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

func main() {
	// 定义命令行参数
	flag.StringVar(&cliTitle, "title", "", "消息标题")
	flag.StringVar(&cliContent, "content", "", "消息内容")
	flag.StringVar(&cliAppID, "appid", "", "AppID")
	flag.StringVar(&cliSecret, "secret", "", "AppSecret")
	flag.StringVar(&cliUserID, "userid", "", "openid")
	flag.StringVar(&cliTemplateID, "template_id", "", "模板ID")
	flag.StringVar(&cliBaseURL, "base_url", "", "跳转url")
	flag.StringVar(&cliTimezone, "tz", "Asia/Shanghai", "时区，默认东八区")
	flag.StringVar(&startPort, "port", "", "端口")

	// 解析命令行参数
	flag.Parse()

	// 设置路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `go-wxpush is running...✅`)
	})
	http.HandleFunc("/wxsend", handleWxSend)
	http.HandleFunc("/detail", handleDetail)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/api/config", handleConfig)

	// 启动服务器
	//fmt.Println("Server is running on port 5566...")
	port := "5566"
	if startPort != "" {
		port = startPort
	}
	fmt.Println("Server is running on： " + "http://127.0.0.1:" + port)

	err := http.ListenAndServe(":"+port, nil)

	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}

}

// 嵌入静态HTML文件
//
//go:embed msg_detail.html admin.html
var htmlContent embed.FS

// 处理管理页面请求
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	htmlData, err := htmlContent.ReadFile("admin.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "无法读取嵌入的 HTML 文件: %v"}`, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlData)
}

// 处理配置持久化请求
func handleConfig(w http.ResponseWriter, r *http.Request) {
	configFile := "config.json"
	if r.Method == "GET" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			if os.IsNotExist(err) {
				w.Write([]byte("{}"))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error": "%v"}`, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	} else if r.Method == "POST" {
		var params RequestParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error": "无效的 JSON: %v"}`, err)
			return
		}
		// 只保存配置相关的字段
		configData := map[string]string{
			"appid":       params.AppID,
			"secret":      params.Secret,
			"userid":      params.UserID,
			"template_id": params.TemplateID,
			"base_url":    params.BaseURL,
		}
		data, _ := json.MarshalIndent(configData, "", "  ")
		if err := os.WriteFile(configFile, data, 0644); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error": "保存失败: %v"}`, err)
			return
		}
		fmt.Fprintf(w, `{"message": "保存成功"}`)
	}
}

// 处理详情页面请求
func handleDetail(w http.ResponseWriter, r *http.Request) {
	// 从嵌入的资源中读取HTML内容
	htmlData, err := htmlContent.ReadFile("msg_detail.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "Failed to read embedded HTML file: %v"}`, err)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 返回HTML内容
	w.Write(htmlData)
}

func handleWxSend(w http.ResponseWriter, r *http.Request) {

	// 解析参数
	var params RequestParams

	// 根据请求方法解析参数
	if r.Method == "POST" {
		// 解析JSON请求体
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error": "Invalid JSON format: %v"}`, err)
			return
		}
	} else if r.Method == "GET" {
		// 解析GET查询参数
		params.Title = r.URL.Query().Get("title")
		params.Content = r.URL.Query().Get("content")
		params.AppID = r.URL.Query().Get("appid")
		params.Secret = r.URL.Query().Get("secret")
		params.UserID = r.URL.Query().Get("userid")
		params.TemplateID = r.URL.Query().Get("template_id")
		params.BaseURL = r.URL.Query().Get("base_url")
		params.Timezone = r.URL.Query().Get("tz")
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, `{"error": "Method not allowed"}`)
		return
	}

	// 尝试从 config.json 加载持久化配置实现热更新
	if configData, err := os.ReadFile("config.json"); err == nil {
		var savedConfig map[string]string
		if err := json.Unmarshal(configData, &savedConfig); err == nil {
			if params.AppID == "" {
				params.AppID = savedConfig["appid"]
			}
			if params.Secret == "" {
				params.Secret = savedConfig["secret"]
			}
			if params.UserID == "" {
				params.UserID = savedConfig["userid"]
			}
			if params.TemplateID == "" {
				params.TemplateID = savedConfig["template_id"]
			}
			if params.BaseURL == "" {
				params.BaseURL = savedConfig["base_url"]
			}
			if params.Timezone == "" {
				params.Timezone = savedConfig["tz"]
			}
		}
	}

	// 只有当GET/POST参数为空时，才使用命令行参数
	if params.Title == "" && cliTitle != "" {
		params.Title = cliTitle
	}
	if params.Content == "" && cliContent != "" {
		params.Content = cliContent
	}
	if params.AppID == "" && cliAppID != "" {
		params.AppID = cliAppID
	}
	if params.Secret == "" && cliSecret != "" {
		params.Secret = cliSecret
	}
	if params.UserID == "" && cliUserID != "" {
		params.UserID = cliUserID
	}
	if params.TemplateID == "" && cliTemplateID != "" {
		params.TemplateID = cliTemplateID
	}
	if params.BaseURL == "" && cliBaseURL != "" {
		params.BaseURL = cliBaseURL
	}
	if params.Timezone == "" && cliTimezone != "" {
		params.Timezone = cliTimezone
	}

	// 验证必要参数
	if params.AppID == "" || params.Secret == "" || params.UserID == "" || params.TemplateID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "Missing required parameters"}`)
		return
	}
	if params.BaseURL == "" || params.BaseURL == "https://push.hzz.cool/detail" {
		params.BaseURL = "https://push.hzz.cool"
	}
	if params.Content == "" {
		params.Content = "测试内容"
	}
	if params.Title == "" {
		params.Title = "测试标题"
	}

	// 获取AccessToken
	token, err := getAccessToken(params.AppID, params.Secret)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "Failed to get access token: %v"}`, err)
		return
	}

	//log.Println(token)
	// 发送模板消息
	resp, err := sendTemplateMessage(token, params)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "Failed to send template message: %v"}`, err)
		return
	}

	// 返回结果
	json.NewEncoder(w).Encode(resp)
}

// Token请求参数结构体
type TokenRequestParams struct {
	GrantType    string `json:"grant_type"`
	AppID        string `json:"appid"`
	Secret       string `json:"secret"`
	ForceRefresh bool   `json:"force_refresh"`
}

func getAccessToken(appid, secret string) (string, error) {
	cacheKey := appid + "_" + secret

	// 检查缓存
	cacheMu.Lock()
	cache, ok := tokenCacheMap[cacheKey]
	if !ok {
		cache = &TokenCache{}
		tokenCacheMap[cacheKey] = cache
	}
	cacheMu.Unlock()

	cache.mu.RLock()
	if cache.AccessToken != "" && time.Now().Before(cache.ExpireTime) {
		token := cache.AccessToken
		cache.mu.RUnlock()
		return token, nil
	}
	cache.mu.RUnlock()

	// 缓存失效，获取新 Token
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 双重检查，防止并发请求多次刷新
	if cache.AccessToken != "" && time.Now().Before(cache.ExpireTime) {
		return cache.AccessToken, nil
	}

	// 构建请求参数
	requestParams := TokenRequestParams{
		GrantType:    "client_credential",
		AppID:        appid,
		Secret:       secret,
		ForceRefresh: false,
	}

	// 转换为JSON
	jsonData, err := json.Marshal(requestParams)
	if err != nil {
		return "", err
	}

	// 忽略证书验证
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 发送POST请求
	resp, err := client.Post("https://api.weixin.qq.com/cgi-bin/stable_token", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 解析响应
	var tokenResp AccessTokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", err
	}

	if tokenResp.Errcode != 0 {
		return "", fmt.Errorf("微信接口错误: %s (code: %d)", tokenResp.Errmsg, tokenResp.Errcode)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("未能获取到 access_token, 响应内容: %s", string(body))
	}

	// 更新缓存 (提前 5 分钟过期以确保安全)
	cache.AccessToken = tokenResp.AccessToken
	cache.ExpireTime = time.Now().Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second)

	fmt.Printf("[%s] 已刷新 AccessToken, 有效期至: %s\n", time.Now().Format("15:04:05"), cache.ExpireTime.Format("15:04:05"))

	return cache.AccessToken, nil
}

func sendTemplateMessage(accessToken string, params RequestParams) (WechatAPIResponse, error) {
	// 构建请求URL
	apiUrl := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=%s", accessToken)

	// 处理时区，默认东八区
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location, _ = time.LoadLocation("Asia/Shanghai") // 确保默认使用东八区
	}

	// 如果参数中有时区，则尝试使用该时区
	if params.Timezone != "" {
		loc, err := time.LoadLocation(params.Timezone)
		if err == nil {
			location = loc
		}
	}

	// 获取当前时间
	currentTime := time.Now().In(location)
	timeStr := currentTime.Format("2006-01-02 15:04:05")

	// 构建请求数据
	requestData := TemplateMessageRequest{
		ToUser:     params.UserID,
		TemplateID: params.TemplateID,
		URL:        params.BaseURL + `/detail?title=` + url.QueryEscape(params.Title) + `&message=` + url.QueryEscape(params.Content) + `&date=` + url.QueryEscape(timeStr),
		Data: map[string]interface{}{
			"title": map[string]string{
				"value": params.Title,
			},
			"content": map[string]string{
				"value": params.Content,
			},
		},
	}

	// 转换为JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return WechatAPIResponse{}, err
	}

	// 忽略证书验证
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 发送POST请求
	resp, err := client.Post(apiUrl, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return WechatAPIResponse{}, err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return WechatAPIResponse{}, err
	}

	// 解析响应
	var apiResp WechatAPIResponse
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		return WechatAPIResponse{}, err
	}

	return apiResp, nil
}
