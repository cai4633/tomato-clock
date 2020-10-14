var _a = getApp().globalData, host = _a.host, t_app_id = _a.t_app_id, t_app_secret = _a.t_app_secret;
var _http = function (method, url, data) {
    return new Promise(function (resolve, reject) {
        wx.request({
            method: method,
            url: "" + host + url,
            data: data,
            dataType: 'json',
            header: {
                Authorization: "Bearer " + wx.getStorageSync('X-token'),
                "t-app-id": t_app_id,
                "t-app-secret": t_app_secret
            },
            success: function (res) {
                var statusCode = res.statusCode;
                if (statusCode >= 400) {
                    if (statusCode === 401) {
                        wx.redirectTo({
                            url: '/pages/login/login',
                        });
                    }
                    reject(res);
                }
                else {
                    resolve(res);
                }
            },
            fail: function (error) {
                wx.showToast({
                    title: '请求失败',
                });
                reject(error);
            }
        });
    }).catch(function (e) {
        console.log(e);
    });
};
export var http = {
    get: function (url, param) { return _http('GET', url, param); },
    post: function (url, data) { return _http('POST', url, data); },
    put: function (url, data) { return _http('PUT', url, data); },
    delete: function (url, data) { return _http('DELETE', url, data); },
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaHR0cC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImh0dHAudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQU0sSUFBQSx3QkFJaUIsRUFIckIsY0FBSSxFQUNKLHNCQUFRLEVBQ1IsOEJBQ3FCLENBQUE7QUFRdkIsSUFBTSxLQUFLLEdBQUcsVUFBQyxNQUFpRCxFQUFFLEdBQVcsRUFBRSxJQUFTO0lBQ3RGLE9BQU8sSUFBSSxPQUFPLENBQW1CLFVBQUMsT0FBTyxFQUFFLE1BQU07UUFDbkQsRUFBRSxDQUFDLE9BQU8sQ0FBQztZQUNULE1BQU0sUUFBQTtZQUNOLEdBQUcsRUFBRSxLQUFHLElBQUksR0FBRyxHQUFLO1lBQ3BCLElBQUksTUFBQTtZQUNKLFFBQVEsRUFBRSxNQUFNO1lBQ2hCLE1BQU0sRUFBRTtnQkFDTixhQUFhLEVBQUUsWUFBVSxFQUFFLENBQUMsY0FBYyxDQUFDLFNBQVMsQ0FBRztnQkFDdkQsVUFBVSxFQUFFLFFBQVE7Z0JBQ3BCLGNBQWMsRUFBRSxZQUFZO2FBQzdCO1lBQ0QsT0FBTyxFQUFFLFVBQUMsR0FBbUQ7Z0JBRXpELElBQUEsMkJBQVUsQ0FDTDtnQkFDUCxJQUFJLFVBQVUsSUFBSSxHQUFHLEVBQUU7b0JBQ3JCLElBQUksVUFBVSxLQUFLLEdBQUcsRUFBRTt3QkFDdEIsRUFBRSxDQUFDLFVBQVUsQ0FBQzs0QkFDWixHQUFHLEVBQUUsb0JBQW9CO3lCQUMxQixDQUFDLENBQUE7cUJBQ0g7b0JBQ0QsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2lCQUNaO3FCQUFNO29CQUNMLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQTtpQkFDYjtZQUNILENBQUM7WUFDRCxJQUFJLFlBQUMsS0FBSztnQkFDUixFQUFFLENBQUMsU0FBUyxDQUFDO29CQUNYLEtBQUssRUFBRSxNQUFNO2lCQUNkLENBQUMsQ0FBQTtnQkFDRixNQUFNLENBQUMsS0FBSyxDQUFDLENBQUE7WUFDZixDQUFDO1NBQ0YsQ0FBQyxDQUFBO0lBQ0osQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLFVBQUMsQ0FBQztRQUNULE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFFakIsQ0FBQyxDQUFDLENBQUE7QUFDSixDQUFDLENBQUE7QUFFRCxNQUFNLENBQUMsSUFBTSxJQUFJLEdBQUc7SUFDbEIsR0FBRyxFQUFFLFVBQUMsR0FBVyxFQUFFLEtBQVcsSUFBSyxPQUFBLEtBQUssQ0FBQyxLQUFLLEVBQUUsR0FBRyxFQUFFLEtBQUssQ0FBQyxFQUF4QixDQUF3QjtJQUMzRCxJQUFJLEVBQUUsVUFBQyxHQUFXLEVBQUUsSUFBVSxJQUFLLE9BQUEsS0FBSyxDQUFDLE1BQU0sRUFBRSxHQUFHLEVBQUUsSUFBSSxDQUFDLEVBQXhCLENBQXdCO0lBQzNELEdBQUcsRUFBRSxVQUFDLEdBQVcsRUFBRSxJQUFTLElBQUssT0FBQSxLQUFLLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxJQUFJLENBQUMsRUFBdkIsQ0FBdUI7SUFDeEQsTUFBTSxFQUFFLFVBQUMsR0FBVyxFQUFFLElBQVMsSUFBSyxPQUFBLEtBQUssQ0FBQyxRQUFRLEVBQUUsR0FBRyxFQUFFLElBQUksQ0FBQyxFQUExQixDQUEwQjtDQUMvRCxDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiY29uc3Qge1xyXG4gIGhvc3QsXHJcbiAgdF9hcHBfaWQsXHJcbiAgdF9hcHBfc2VjcmV0XHJcbn0gPSBnZXRBcHAoKS5nbG9iYWxEYXRhXHJcblxyXG5pbnRlcmZhY2UgUHJvbWlzZVZhbHVlVHlwZSB7XHJcbiAgZGF0YTogc3RyaW5nIHwgV2VjaGF0TWluaXByb2dyYW0uSUFueU9iamVjdFxyXG4gIGhlYWRlcjogV2VjaGF0TWluaXByb2dyYW0uSUFueU9iamVjdFxyXG4gIHN0YXR1c0NvZGU6IG51bWJlclxyXG4gIGVyck1zZzogc3RyaW5nXHJcbn1cclxuY29uc3QgX2h0dHAgPSAobWV0aG9kOiBXZWNoYXRNaW5pcHJvZ3JhbS5SZXF1ZXN0T3B0aW9uWydtZXRob2QnXSwgdXJsOiBzdHJpbmcsIGRhdGE6IGFueSkgPT4ge1xyXG4gIHJldHVybiBuZXcgUHJvbWlzZTxQcm9taXNlVmFsdWVUeXBlPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICB3eC5yZXF1ZXN0KHtcclxuICAgICAgbWV0aG9kLFxyXG4gICAgICB1cmw6IGAke2hvc3R9JHt1cmx9YCxcclxuICAgICAgZGF0YSxcclxuICAgICAgZGF0YVR5cGU6ICdqc29uJyxcclxuICAgICAgaGVhZGVyOiB7XHJcbiAgICAgICAgQXV0aG9yaXphdGlvbjogYEJlYXJlciAke3d4LmdldFN0b3JhZ2VTeW5jKCdYLXRva2VuJyl9YCxcclxuICAgICAgICBcInQtYXBwLWlkXCI6IHRfYXBwX2lkLFxyXG4gICAgICAgIFwidC1hcHAtc2VjcmV0XCI6IHRfYXBwX3NlY3JldFxyXG4gICAgICB9LFxyXG4gICAgICBzdWNjZXNzOiAocmVzOiBXZWNoYXRNaW5pcHJvZ3JhbS5SZXF1ZXN0U3VjY2Vzc0NhbGxiYWNrUmVzdWx0KSA9PiB7XHJcbiAgICAgICAgY29uc3Qge1xyXG4gICAgICAgICAgc3RhdHVzQ29kZVxyXG4gICAgICAgIH0gPSByZXNcclxuICAgICAgICBpZiAoc3RhdHVzQ29kZSA+PSA0MDApIHtcclxuICAgICAgICAgIGlmIChzdGF0dXNDb2RlID09PSA0MDEpIHtcclxuICAgICAgICAgICAgd3gucmVkaXJlY3RUbyh7XHJcbiAgICAgICAgICAgICAgdXJsOiAnL3BhZ2VzL2xvZ2luL2xvZ2luJyxcclxuICAgICAgICAgICAgfSlcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHJlamVjdChyZXMpXHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgIHJlc29sdmUocmVzKVxyXG4gICAgICAgIH1cclxuICAgICAgfSxcclxuICAgICAgZmFpbChlcnJvcikge1xyXG4gICAgICAgIHd4LnNob3dUb2FzdCh7XHJcbiAgICAgICAgICB0aXRsZTogJ+ivt+axguWksei0pScsXHJcbiAgICAgICAgfSlcclxuICAgICAgICByZWplY3QoZXJyb3IpXHJcbiAgICAgIH1cclxuICAgIH0pXHJcbiAgfSkuY2F0Y2goKGUpPT57XHJcbiAgICBjb25zb2xlLmxvZyhlKTtcclxuICAgIFxyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBodHRwID0ge1xyXG4gIGdldDogKHVybDogc3RyaW5nLCBwYXJhbT86IGFueSkgPT4gX2h0dHAoJ0dFVCcsIHVybCwgcGFyYW0pLFxyXG4gIHBvc3Q6ICh1cmw6IHN0cmluZywgZGF0YT86IGFueSkgPT4gX2h0dHAoJ1BPU1QnLCB1cmwsIGRhdGEpLFxyXG4gIHB1dDogKHVybDogc3RyaW5nLCBkYXRhOiBhbnkpID0+IF9odHRwKCdQVVQnLCB1cmwsIGRhdGEpLFxyXG4gIGRlbGV0ZTogKHVybDogc3RyaW5nLCBkYXRhOiBhbnkpID0+IF9odHRwKCdERUxFVEUnLCB1cmwsIGRhdGEpLFxyXG59Il19