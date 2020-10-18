import { TodoListItem, TomatoItem } from '../../../typings/types/index';

const dayjs = require('dayjs')
function rankByDate(data: (TomatoItem | TodoListItem)[]) {
  const obj: { [key: string]: any[] } = {}
  data.forEach((item) => {
    const date = dayjs(item.createdAt).format('MMDD')
    if (!(date in obj)) {
      obj[date] = []
    }
    obj[date].push(item)
  })
  const keys = Object.keys(obj).sort((a, b) => parseInt(b) - parseInt(a))
  return keys.map((key: string) => {
    return [[key], obj[key]]
  })
}

export { rankByDate }