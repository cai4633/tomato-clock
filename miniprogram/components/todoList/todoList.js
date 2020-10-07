// components/todoList/todoList.js
Component({

  /**
   * 页面的初始数据
   */
  data: {

  },
  properties: {
    list: {
      type: Array,
      value: []
    }
  },

  methods: {
    ontab(e) {
      this.triggerEvent('toggle', e.currentTarget.id)
    }
  }

})