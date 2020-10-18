import {
  createTomato,
  updateTomato
} from '../../api/todo';
import {
  http
} from '../../api/http'
import {
  padLeft
} from '../../common/js/utils';
Page({
  timer: null,
  data: {
    totalTime: 1500,
    remaining: 1500,
    time: '',
    isPause: true,
    isFinished: false,
    abandonConfirmVisible: false,
    finishConfirmVisible: false,
    tomato: null
  },
  formatTime(remaining) {
    this.setData({
      time: padLeft(remaining / 60 | 0) + ':' + padLeft(remaining % 60)
    })
  },

  clearTimer() {
    this.timer && clearInterval(this.timer)
  },
  timePause() { //暂停
    this.setData({
      isPause: true
    })
  },
  timeStart() {
    this.formatTime(this.data.remaining) //init 显示时间
    this.setData({
      isPause: false,
      isFinished: false
    })
    if (!this.timer) { //无计时器,添加计时器
      this.timer = setInterval(() => {
        const {
          isPause,
          remaining
        } = this.data
        if (!isPause) {
          this.setData({
            remaining: remaining - 1,
          })
          this.formatTime(this.data.remaining)
          if (remaining - 1 <= 0) { //倒计时结束
            this.setData({
              remaining: this.data.totalTime,
              isPause: true,
              isFinished: true,
              finishConfirmVisible: true
            })
            clearInterval(this.timer)
            this.timer = null
          }
        }
      }, 1000)
    }
  },

  showConfirm() {
    this.setData({
      isPause: true,
      abandonConfirmVisible: true
    })
  },
  hideConfirm() {
    this.setData({
      isPause: false,
      abandonConfirmVisible: false
    })
  },

  abandon() {
    this.showConfirm()
  },
  cancelAbandon() {
    this.hideConfirm()
  },
  confirmAbandon(e) {
    const {
      objectId
    } = this.data.tomato
    updateTomato({
      objectId,
      description: e.detail,
      aborted: true
    }).then((response) => {
      this.setData({
        isFinished: true
      })
      wx.navigateBack()
    })
    this.hideConfirm()
  },
  hideFinishConfirm() {
    this.setData({
      finishConfirmVisible: false
    });
  },
  confirmFinish(e) {
    updateTomato({
      objectId: this.data.tomato.objectId,
      description: e.detail,
      aborted: false
    })
    this.hideFinishConfirm();
  },
  cancelFinish() {
    this.hideFinishConfirm()
  },
  onReady: function () {
    this.timeStart()
    createTomato().then(response => {
      this.setData({
        tomato: response
      })
    })
  },

  defaultAbandon() {
    this.clearTimer()
    if (!this.data.isFinished) {
      updateTomato({
        objectId: this.data.tomato.objectId,
        description: '放弃番茄',
        aborted: true
      })
    }
  },

  onHide: function () {
    this.defaultAbandon()
  },

  onUnload: function () {
    this.defaultAbandon()
  },
})