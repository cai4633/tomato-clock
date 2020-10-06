// components/tButton/tButton.js
Component({

  /**
   * 页面的初始数据
   */
  data: {},
  properties: {
    click: {
      type: Function
    },
    text: {
      type: String,
      value: '',
    },
    size: {
      type: String,
      value: ''
    },
    type: {
      // type: 'padding', 'border', 'primary', 'warn', 'default'
      type: String,
      value: '',
    }
  },
  methods: {
    ontab(e) {
      this.triggerEvent('btnClick', e)
    }
  }

})