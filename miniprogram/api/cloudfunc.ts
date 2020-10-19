wx.cloud.init({
    env: 'tomato-clock-9ga9k3bv3918b714',
});

export function secureCheck(content: string) {
    let sec = true;
    return new Promise((resolve, reject) => {
        wx.cloud.callFunction({
            name: 'msgSecCheck',
            data: {
                content
            },
            success: function (res) {
                if (res && typeof res.result === 'object') {
                    sec = (res.result.errCode === 0);
                }
            },
            fail: function () {
                sec = false;
            },
            complete: function (value) {
                if (!sec) {
                    wx.showToast({
                        title: '文本含有违法违规内容',
                        icon: 'none',
                        mask: true,
                    });
                    reject(value)
                } else {
                    resolve(value)
                }
            }
        });
    })
}