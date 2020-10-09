const {
  host,
  t_app_id,
  t_app_secret
} = getApp().globalData


const _http = (method, url, data) => {
  return new Promise((resolve, reject) => {
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
      success: (res) => {
        const {
          statusCode
        } = res
        if (statusCode >= 400) {
          reject(res, statusCode)
        } else {
          resolve(res, statusCode)
        }
      },
      fail(error) {
        wx.showToast({
          title: '请求失败',
        })
        reject(error)
      }
    })
  })
}

export const http = {
  get: (url, param) => _http('GET', url, param),
  post: (url, data) => _http('POST', url, data),
  put: (url, data) => _http('PUT', url, data),
  delete: (url, data) => _http('DELETE', url, data),
}