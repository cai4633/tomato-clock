import { http } from './http';

const getTodoList = () => {
  return http.get('/todos?completed=false').then((res) => {
    if (res && typeof res.data === "object") {
      return res.data.resources
    }
    return []
  })
}

const createTodoItem = (description: string) => {
  return http.post('/todos', { description }).then(res => {
    return (res && typeof res.data === "object") ? res.data.resource : []
  })
}

const deleteTodoItem = (id: number) => {
  return http.put(`/todos/${id}`, { completed: true }).then((res) => res && res.data)
}
const updateTodoItem = (id: number, description: string) => {
  return http.put(`/todos/${id}`, { completed: false, description }).then((res) => ( res && typeof res.data === "object") ? res.data.resource : [])
}

const createTomato = () => {
  return http.post('/tomatoes').then((res) => {
    return res && typeof res.data === 'object' ? res.data.resource : []
  })
}

interface ParamType {
  id: number
  description: string
  aborted: boolean
}
const updateTomato = (param: ParamType) => {
  const { id, description, aborted } = param
  return http.put(`/tomatoes/${id}`, {
    description, aborted
  }).then(res => res && typeof res.data === 'object' ? res.data.resource : [])
}
export { getTodoList, createTodoItem, deleteTodoItem, updateTodoItem, createTomato, updateTomato }