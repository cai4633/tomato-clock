// components/tConfirm/tConfirm.js
Component({
  data: {
    value: ''
  },
  properties: {
    defaultValue: {
      type: String,
      value: ''
    },
    visible: {
      type: Boolean,
      value: false
    },
    placeholder: {
      type: String,
      value: '请输入'
    }
  },
  methods: {
    cancel() {
      this.triggerEvent('cancel')
    },
    enter() {
      this.triggerEvent('enter', this.data.value)
      this.reset()
    },
    reset() {
      this.setData({
        value: ''
      })
    },
    changeValue(e) {
      this.setData({
        value: e.detail.value
      })
    }
  }
})