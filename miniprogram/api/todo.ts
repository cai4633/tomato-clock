import { http } from './http';

const getTodoList = () => {
  return http.get('/todos?completed=false').then((res) => {
    if (typeof res.data === "object") {
      return res.data.resources
    }
    return []
  })
}

const createTodoItem = (description: string) => {
  return http.post('/todos', { description }).then(res => {
    return (typeof res.data === "object") ? res.data.resource : []
  })
}

const deleteTodoItem = (id: number) => {
  return http.put(`/todos/${id}`, { completed: true }).then((res) => res.data)
}
const updateTodoItem = (id: number, description: string) => {
  return http.put(`/todos/${id}`, { completed: false, description }).then((res) => res.data)
}
export { getTodoList, createTodoItem, deleteTodoItem, updateTodoItem }