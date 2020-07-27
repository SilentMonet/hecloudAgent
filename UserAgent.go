package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
UserAgent  用户客户端对象
*/
type UserAgent struct {
	user   userInfo
	disk   diskInfo
	cookie cookie
	client *http.Client
}
type cookie struct {
	RMKEY string
	sid   string
}
type userInfo struct {
	name              string
	password          string
	encryptedPassword string
}
type diskInfo struct {
	TotalSize   int
	UsedSize    int `json:"useSize"`
	FreeSize    int
	FileMaxSize int
	RootID      string
}

/* 用户名及密码 */
const (
	Name1     = "1XXXXXXXXX"
	Password1 = "*****"
)

/* 校验cookie */
func testCookie(cookie cookie) bool {
	client := &http.Client{}
	var req *http.Request
	req, _ = http.NewRequest("POST", "https://mcloud.139.com/setting/s?func=user:getCommConfig&sid="+cookie.sid, strings.NewReader(`<object><int name="configId">608</int></object>`))
	req.AddCookie(&http.Cookie{Name: "RMKEY", Value: cookie.RMKEY})
	req.AddCookie(&http.Cookie{Name: "Os_SSo_Sid", Value: cookie.sid})
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer resp.Body.Close()
	var r map[string]interface{}
	p, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	if err := json.Unmarshal(p, &r); err == nil && r["code"] == "S_OK" {
		return true
	} else {
		fmt.Println(err)
	}
	return false
}

/*getCookie  获取RMKEY、sid*/
func (agent *UserAgent) getCookie() cookie {
	var cookie cookie
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	var req http.Request
	req.ParseForm()
	req.Form.Add("UserName", agent.user.name)
	req.Form.Add("Password", agent.user.encryptedPassword)
	req.Form.Add("auto", "1")
	body := strings.TrimSpace(req.Form.Encode())
	request, err := http.NewRequest("POST", "http://mcloud.139.com/Login/Login.ashx?authType=2&clientid=10804", strings.NewReader(body))
	if err != nil {
		fmt.Println(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var resp *http.Response
	resp, err = client.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	for _, v := range resp.Cookies() {
		switch v.Name {
		case "RMKEY":
			cookie.RMKEY = v.Value
		case "Os_SSo_Sid":
			cookie.sid = v.Value
		}
	}
	agent.cookie = cookie
	return cookie
}

func (agent UserAgent) diskInit() (diskInfo, error) {
	var r struct {
		Code    string
		Summary string
		Disk    struct {
			BaseInfo diskInfo
		} `json:"var"`
	}
	resp, err := agent.client.Post("https://mcloud.139.com/file/disk?func=disk:init&sid="+agent.cookie.sid, "text/plain", strings.NewReader(""))
	if err != nil {
		fmt.Println(err)
		return diskInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &r)
	if r.Code != "S_OK" {
		err = errors.New(r.Summary)
	}
	return r.Disk.BaseInfo, err
}

func (agent UserAgent) diskLoginCaiyun() (*http.Response, error) {
	url := "https://mcloud.139.com/file/disk?func=disk:loginCaiyun&sid=" + agent.cookie.sid
	body := `<object><string name="channel">10213404</string><string name="logKey">Wap.Home.Onlinepreview</string></object>`
	return agent.client.Post(url, "text/plain", strings.NewReader(body))
}

func (agent UserAgent) diskIndex() (*http.Response, error) {
	url := "https://mcloud.139.com/file/disk?func=disk:index&sid=" + agent.cookie.sid
	return agent.client.Post(url, "text/plain", strings.NewReader(""))
}

type diskNode struct {
	ID        string
	Name      string
	Type      string
	Directory struct {
		DirectoryLevel    int
		ParentDirectoryID string
		DirFlag           int
		FileNum           int
		DirType           int
	}
	File struct {
		DirectoryID     string
		FileSize        int
		RawSize         int
		ext             string
		ThumbnailURL    string
		BigthumbnailURL string
		PresentURL      string
		PresentLURL     string
		PresentHURL     string
	}
	IsShare    int
	CreateTime string
	ModifyTime string
}

func (agent UserAgent) diskList(directoryID string) ([]diskNode, error) {
	var r struct {
		Code    string
		Summary string
		Var     struct {
			DirectoryCount int
			FileCount      int
			TotalSize      int
			Files          []diskNode
		}
	}
	url := "https://mcloud.139.com/file/disk?func=disk:fileListPage&sid=" + agent.cookie.sid
	body := `<object>
									 <string name="directoryId">` + directoryID + `</string>
									 <int name="dirType">0</int>
									 <int name="toPage">1</int>
									 <int name="pageSize">20</int>
									 <string name="thumbnailSize">65*65</string>
								 </object>`
	resp, err := agent.client.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "S_OK" {
		err = errors.New(r.Summary)
	}
	return r.Var.Files, err
}

func (agent UserAgent) diskCreateDir(parentDir string, dirName string) (directoryID string, err error) {
	var r struct {
		Code    string
		Summary string
		Var     struct {
			DirectoryID string
		}
	}
	url := "https://mcloud.139.com/file/disk?func=disk:createDirectory&sid=" + agent.cookie.sid
	body :=
		`
	  <object>
      <string name="parentId">` + parentDir + `</string>
      <int name="dirType">1</int>
      <string name="name">` + dirName + `</string>
		</object>`
	resp, err := agent.client.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bytesContainer, &r)
	if r.Code != "S_OK" {
		err = errors.New(r.Summary)
	}
	return r.Var.DirectoryID, err
}

func (agent UserAgent) diskDelete(dirIDs []string, fileIDs []string) error {
	var r struct {
		Code    string
		Summary string
	}
	url := "https://mcloud.139.com/file/disk?func=disk:mgtVirDirInfo&sid=" + agent.cookie.sid
	body := `
	  <object>
      <string name="directoryIds">` + strings.Join(dirIDs, ",") + `</string>
      <string name="fileIds">` + strings.Join(fileIDs, ",") + `</string>
      <int name="opr">2</int>
		</object>`
	resp, err := agent.client.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "" && r.Code != "S_OK" {
		return errors.New(r.Summary)
	}
	return err
}

func (agent UserAgent) diskMove(dirIDs []string, fileIDs []string, targetDir string) error {
	var r struct {
		Code    string
		Summary string
	}
	url := "https://mcloud.139.com/file/disk?func=disk:move&sid=" + agent.cookie.sid
	body := `
	  <object>
      <string name="fileIds">` + strings.Join(fileIDs, ",") + `</string>
      <string name="directoryIds" >` + strings.Join(dirIDs, ",") + `<string name="directoryIds" />
      <string name="toDirectoryId">` + targetDir + `</string>
      <int name="toDirType">1</int>
    </object>
	`
	resp, err := agent.client.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "" && r.Code != "S_OK" {
		return errors.New(r.Summary)
	}
	return err
}

func (agent UserAgent) diskRename(nodeID string, name string, isDir bool) error {
	var r struct {
		Code    string
		Summary string
	}
	url := "https://mcloud.139.com/file/disk?func=disk:rename&sid=" + agent.cookie.sid
	var body string
	if isDir {
		body = `
	  <object>
      <string name="name">` + name + `</string>
      <string name="directoryId">` + nodeID + `</string>
      <string name="dirType">1</string>
    </object>
	`
	} else {
		body = `
	  <object>
      <string name="name">` + name + `</string>
      <string name="fileId">` + nodeID + `</string>
    </object>
	`
	}
	resp, err := agent.client.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "" && r.Code != "S_OK" {
		return errors.New(r.Summary)
	}
	return err
}

func (agent UserAgent) diskUpload(filepath string, filename string, dirID string) error {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return err
	}
	md5str, err := calcMD5(filepath)
	if err != nil {
		return err
	}
	apiURL := `https://mcloud.139.com/file/disk?func=disk:fastUpload&sid=` + agent.cookie.sid
	body := `<object>
  <string name="fileName">` + filename + `</string>
  <int name="fileSize">` + strconv.FormatInt(fileInfo.Size(), 10) + `</int>
  <string name="fileMd5">` + md5str + `</string>
  <string name="directoryId">` + dirID + `</string>
  <string name="dirType">0</string>
  <string name="channel">10213404</string>
  <string name="version">66</string>
  </object>
	`
	fmt.Println(body)
	resp, err := agent.client.Post(apiURL, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	var r struct {
		Code    string
		Summary string
		Var     struct {
			Status    int
			URL       string
			FileID    string
			PostParam struct {
				Authorization string
				UploadTaskID  string
				ContentSize   string
			}
		}
	}
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "" && r.Code != "S_OK" {
		return errors.New(r.Summary)
	}
	uploadURL := r.Var.URL

	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	req, _ := http.NewRequest("POST", uploadURL, file)
	req.Header.Add("Authorization", r.Var.PostParam.Authorization)
	req.Header["contentSize"] = []string{r.Var.PostParam.ContentSize}
	req.Header.Set("Content-Length", r.Var.PostParam.ContentSize)
	req.Header["range"] = []string{"bytes=0-" + strconv.FormatInt(fileInfo.Size()-1, 10)}
	req.Header["UploadtaskID"] = []string{r.Var.PostParam.UploadTaskID}
	req.Header["x-NameCoding"] = []string{"urlencoding"}
	req.Header["Content-Type"] = []string{"application/octet-stream;name=" + url.QueryEscape(filename)}

	uploadResult, err := agent.client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	bytesContainer, _ = ioutil.ReadAll(uploadResult.Body)
	fmt.Println(string(bytesContainer))
	return nil
}

func (agent UserAgent) diskDownload(target diskNode, osPath string) error {
	if target.Type == "directory" {
		return errors.New("下载目标为目录！不可下载！")
	}
	apiURL := "https://mcloud.139.com/file/disk?func=disk:download&sid=" + agent.cookie.sid
	body := `
	  <object>
    <int name="dirType">0</int>
    <string name="directoryIds" />
    <null name="parentDirType" />
    <string name="fileIds">` + target.ID + `</string>
    <string name="channel">10213404</string>
    <string name="clienttype">651</string>
    <int name="isFriendShare">0</int>
    </object>
	`
	var r struct {
		Code    string
		Summary string
		Var     struct {
			URL string
		}
	}
	resp, err := agent.client.Post(apiURL, "text/plain", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytesContainer, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bytesContainer, &r)
	if r.Code != "" && r.Code != "S_OK" {
		return errors.New(r.Summary)
	}

	downloadURL := r.Var.URL
	err = download(downloadURL, osPath)
	if err != nil {
		return err
	}
	return err
}

/* agent 初始化 */
func (agent *UserAgent) init(userName string) error {
	cookie := getLastCookie(&agent.user)
	if testCookie(cookie) {
		agent.cookie = cookie
	} else {
		cookie = agent.getCookie()
		if testCookie(cookie) {
			agent.cookie = cookie
			updateCookie(agent.user, agent.cookie)
		} else {
			return errors.New("身份验证失败！")
		}
	}
	agent.client = &http.Client{
		Timeout: 20 * time.Second,
	}
	agent.client.Jar, _ = cookiejar.New(nil)
	domain, _ := url.Parse("https://mcloud.139.com")
	agent.client.Jar.SetCookies(domain, []*http.Cookie{&http.Cookie{Name: "RMKEY", Value: agent.cookie.RMKEY}, &http.Cookie{Name: "Os_SSo_Sid", Value: agent.cookie.sid}})
	disk, err := agent.diskInit()
	if err != nil {
		return errors.New("云盘信息初始化失败 ！" + err.Error())
	}
	agent.disk = disk
	return nil
}
