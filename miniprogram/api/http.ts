const {
  host,
  t_app_id,
  t_app_secret
} = getApp().globalData

interface PromiseValueType {
  data: string | WechatMiniprogram.IAnyObject
  header: WechatMiniprogram.IAnyObject
  statusCode: number
  errMsg: string
}
const _http = (method: WechatMiniprogram.RequestOption['method'], url: string, data: any) => {
  return new Promise<PromiseValueType>((resolve, reject) => {
    wx.request({
      method,
      url: `${host}${url}`,
      data,
      dataType: 'json',
      header: {
        Authorization: `Bearer ${wx.getStorageSync('X-token')}`,
        "t-app-id": t_app_id,
        "t-app-secret": t_app_secret
      },
      success: (res: WechatMiniprogram.RequestSuccessCallbackResult) => {
        const {
          statusCode
        } = res
        if (statusCode >= 400) {
          if (statusCode === 401) {
            wx.redirectTo({
              url: '/pages/login/login',
            })
          }
          reject(res)
        } else {
          resolve(res)
        }
      },
      fail(error) {
        wx.showToast({
          title: '请求失败',
        })
        reject(error)
      }
    })
  }).catch((e:any)=>{
    console.log(e);
  })
}

export const http = {
  get: (url: string, param?: any) => _http('GET', url, param),
  post: (url: string, data?: any) => _http('POST', url, data),
  put: (url: string, data: any) => _http('PUT', url, data),
  delete: (url: string, data: any) => _http('DELETE', url, data),
}