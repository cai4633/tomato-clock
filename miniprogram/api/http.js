"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
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
    });
};
exports.http = {
    get: function (url, param) { return _http('GET', url, param); },
    post: function (url, data) { return _http('POST', url, data); },
    put: function (url, data) { return _http('PUT', url, data); },
    delete: function (url, data) { return _http('DELETE', url, data); },
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaHR0cC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImh0dHAudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBTSxJQUFBLHdCQUlpQixFQUhyQixjQUFJLEVBQ0osc0JBQVEsRUFDUiw4QkFDcUIsQ0FBQTtBQVF2QixJQUFNLEtBQUssR0FBRyxVQUFDLE1BQWlELEVBQUUsR0FBVyxFQUFFLElBQVM7SUFDdEYsT0FBTyxJQUFJLE9BQU8sQ0FBbUIsVUFBQyxPQUFPLEVBQUUsTUFBTTtRQUNuRCxFQUFFLENBQUMsT0FBTyxDQUFDO1lBQ1QsTUFBTSxRQUFBO1lBQ04sR0FBRyxFQUFFLEtBQUcsSUFBSSxHQUFHLEdBQUs7WUFDcEIsSUFBSSxNQUFBO1lBQ0osUUFBUSxFQUFFLE1BQU07WUFDaEIsTUFBTSxFQUFFO2dCQUNOLGFBQWEsRUFBRSxZQUFVLEVBQUUsQ0FBQyxjQUFjLENBQUMsU0FBUyxDQUFHO2dCQUN2RCxVQUFVLEVBQUUsUUFBUTtnQkFDcEIsY0FBYyxFQUFFLFlBQVk7YUFDN0I7WUFDRCxPQUFPLEVBQUUsVUFBQyxHQUFtRDtnQkFFekQsSUFBQSwyQkFBVSxDQUNMO2dCQUNQLElBQUksVUFBVSxJQUFJLEdBQUcsRUFBRTtvQkFDckIsSUFBSSxVQUFVLEtBQUssR0FBRyxFQUFFO3dCQUN0QixFQUFFLENBQUMsVUFBVSxDQUFDOzRCQUNaLEdBQUcsRUFBRSxvQkFBb0I7eUJBQzFCLENBQUMsQ0FBQTtxQkFDSDtvQkFDRCxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7aUJBQ1o7cUJBQU07b0JBQ0wsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2lCQUNiO1lBQ0gsQ0FBQztZQUNELElBQUksWUFBQyxLQUFLO2dCQUNSLEVBQUUsQ0FBQyxTQUFTLENBQUM7b0JBQ1gsS0FBSyxFQUFFLE1BQU07aUJBQ2QsQ0FBQyxDQUFBO2dCQUNGLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQTtZQUNmLENBQUM7U0FDRixDQUFDLENBQUE7SUFDSixDQUFDLENBQUMsQ0FBQTtBQUNKLENBQUMsQ0FBQTtBQUVZLFFBQUEsSUFBSSxHQUFHO0lBQ2xCLEdBQUcsRUFBRSxVQUFDLEdBQVcsRUFBRSxLQUFXLElBQUssT0FBQSxLQUFLLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUMsRUFBeEIsQ0FBd0I7SUFDM0QsSUFBSSxFQUFFLFVBQUMsR0FBVyxFQUFFLElBQVUsSUFBSyxPQUFBLEtBQUssQ0FBQyxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksQ0FBQyxFQUF4QixDQUF3QjtJQUMzRCxHQUFHLEVBQUUsVUFBQyxHQUFXLEVBQUUsSUFBUyxJQUFLLE9BQUEsS0FBSyxDQUFDLEtBQUssRUFBRSxHQUFHLEVBQUUsSUFBSSxDQUFDLEVBQXZCLENBQXVCO0lBQ3hELE1BQU0sRUFBRSxVQUFDLEdBQVcsRUFBRSxJQUFTLElBQUssT0FBQSxLQUFLLENBQUMsUUFBUSxFQUFFLEdBQUcsRUFBRSxJQUFJLENBQUMsRUFBMUIsQ0FBMEI7Q0FDL0QsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbImNvbnN0IHtcclxuICBob3N0LFxyXG4gIHRfYXBwX2lkLFxyXG4gIHRfYXBwX3NlY3JldFxyXG59ID0gZ2V0QXBwKCkuZ2xvYmFsRGF0YVxyXG5cclxuaW50ZXJmYWNlIFByb21pc2VWYWx1ZVR5cGUge1xyXG4gIGRhdGE6IHN0cmluZyB8IFdlY2hhdE1pbmlwcm9ncmFtLklBbnlPYmplY3RcclxuICBoZWFkZXI6IFdlY2hhdE1pbmlwcm9ncmFtLklBbnlPYmplY3RcclxuICBzdGF0dXNDb2RlOiBudW1iZXJcclxuICBlcnJNc2c6IHN0cmluZ1xyXG59XHJcbmNvbnN0IF9odHRwID0gKG1ldGhvZDogV2VjaGF0TWluaXByb2dyYW0uUmVxdWVzdE9wdGlvblsnbWV0aG9kJ10sIHVybDogc3RyaW5nLCBkYXRhOiBhbnkpID0+IHtcclxuICByZXR1cm4gbmV3IFByb21pc2U8UHJvbWlzZVZhbHVlVHlwZT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgd3gucmVxdWVzdCh7XHJcbiAgICAgIG1ldGhvZCxcclxuICAgICAgdXJsOiBgJHtob3N0fSR7dXJsfWAsXHJcbiAgICAgIGRhdGEsXHJcbiAgICAgIGRhdGFUeXBlOiAnanNvbicsXHJcbiAgICAgIGhlYWRlcjoge1xyXG4gICAgICAgIEF1dGhvcml6YXRpb246IGBCZWFyZXIgJHt3eC5nZXRTdG9yYWdlU3luYygnWC10b2tlbicpfWAsXHJcbiAgICAgICAgXCJ0LWFwcC1pZFwiOiB0X2FwcF9pZCxcclxuICAgICAgICBcInQtYXBwLXNlY3JldFwiOiB0X2FwcF9zZWNyZXRcclxuICAgICAgfSxcclxuICAgICAgc3VjY2VzczogKHJlczogV2VjaGF0TWluaXByb2dyYW0uUmVxdWVzdFN1Y2Nlc3NDYWxsYmFja1Jlc3VsdCkgPT4ge1xyXG4gICAgICAgIGNvbnN0IHtcclxuICAgICAgICAgIHN0YXR1c0NvZGVcclxuICAgICAgICB9ID0gcmVzXHJcbiAgICAgICAgaWYgKHN0YXR1c0NvZGUgPj0gNDAwKSB7XHJcbiAgICAgICAgICBpZiAoc3RhdHVzQ29kZSA9PT0gNDAxKSB7XHJcbiAgICAgICAgICAgIHd4LnJlZGlyZWN0VG8oe1xyXG4gICAgICAgICAgICAgIHVybDogJy9wYWdlcy9sb2dpbi9sb2dpbicsXHJcbiAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICByZWplY3QocmVzKVxyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICByZXNvbHZlKHJlcylcclxuICAgICAgICB9XHJcbiAgICAgIH0sXHJcbiAgICAgIGZhaWwoZXJyb3IpIHtcclxuICAgICAgICB3eC5zaG93VG9hc3Qoe1xyXG4gICAgICAgICAgdGl0bGU6ICfor7fmsYLlpLHotKUnLFxyXG4gICAgICAgIH0pXHJcbiAgICAgICAgcmVqZWN0KGVycm9yKVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBodHRwID0ge1xyXG4gIGdldDogKHVybDogc3RyaW5nLCBwYXJhbT86IGFueSkgPT4gX2h0dHAoJ0dFVCcsIHVybCwgcGFyYW0pLFxyXG4gIHBvc3Q6ICh1cmw6IHN0cmluZywgZGF0YT86IGFueSkgPT4gX2h0dHAoJ1BPU1QnLCB1cmwsIGRhdGEpLFxyXG4gIHB1dDogKHVybDogc3RyaW5nLCBkYXRhOiBhbnkpID0+IF9odHRwKCdQVVQnLCB1cmwsIGRhdGEpLFxyXG4gIGRlbGV0ZTogKHVybDogc3RyaW5nLCBkYXRhOiBhbnkpID0+IF9odHRwKCdERUxFVEUnLCB1cmwsIGRhdGEpLFxyXG59Il19