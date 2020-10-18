import {
  http
} from '../../api/http'
import dayjs from 'dayjs'
import {
  getAllTomatoes,
  getAllCompleted
} from '../../api/me'
import {
  rankByDate
} from '../../common/js/me'
Page({
  data: {
    tabIndex: 1,
    taskList: {}
  },
  onLoad() {
    this.gotoTomato()
  },
  gotoTomato() {
    this.setData({
      tabIndex: 1
    })
    getAllTomatoes().then((res) => {
      this.setData({
        taskList: rankByDate(res)
      })
    })
  },
  gotoTodo() {
    this.setData({
      tabIndex: 2
    })
    getAllCompleted().then((res) => {
      this.setData({
        taskList: rankByDate(res)
      })
    })
  }
})