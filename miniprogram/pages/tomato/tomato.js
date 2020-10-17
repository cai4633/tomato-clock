import {
  createTomato,
  updateTomato
} from '../../api/todo';
import {
  padLeft
} from '../../common/js/utils';
Page({
  timer: null,
  data: {
    totalTime: 5,
    remaining: 5,
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
      abandonConfirmVisible: true
    })
  },
  hideConfirm() {
    this.setData({
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
      id
    } = this.data.tomato
    updateTomato({
      id,
      description: e.detail,
      aborted: true
    }).then((response) => {
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
      id: this.data.tomato.id,
      description: e.detail,
      aborted: false
    }).then((res) => {
      console.log(res);

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
    updateTomato({
      id: this.data.tomato.id,
      description: '放弃番茄',
      aborted: true
    })
  },

  onHide: function () {
    this.defaultAbandon()
  },

  onUnload: function () {
    this.defaultAbandon()
  },
})