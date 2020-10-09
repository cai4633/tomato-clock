// app.ts
App<IAppOption>({
  globalData: {
    host: 'https://gp-server.hunger-valley.com', 
    app_id: "wxda5eb3e23cf59bfd",
    app_secret: "1b782b720d2504479e83533c5d8461ce",
    t_app_id: "L3foKddALZ67NSo1K2e3CpGx",
    t_app_secret: "rhqUPJ1j3VmqcAYwj4WJysfo"
  },
  onLaunch() {
    // 展示本地存储能力
    const logs = wx.getStorageSync('logs') || []
    logs.unshift(Date.now())
    wx.setStorageSync('logs', logs)

    // 获取用户信息
    wx.getSetting({
      success: res => {
        if (res.authSetting['scope.userInfo']) {
          // 已经授权，可以直接调用 getUserInfo 获取头像昵称，不会弹框
          wx.getUserInfo({
            success: res => {
              // 可以将 res 发送给后台解码出 unionId
              this.globalData.userInfo = res.userInfo

              // 由于 getUserInfo 是网络请求，可能会在 Page.onLoad 之后才返回
              // 所以此处加入 callback 以防止这种情况
              if (this.userInfoReadyCallback) {
                this.userInfoReadyCallback(res)
              }
            },
          })
        }
      },
    })
  },
})