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
      this.triggerEvent('toggle', e.currentTarget.dataset.id)
    },
    updateItem(e) {
      const { id, content } = e.currentTarget.dataset
      this.triggerEvent('updateItem', { id, content })
    }
  }

})