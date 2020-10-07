export const createId = (list) => {
  return list[list.length - 1].id + 1
}

export const padLeft = (num) => {
  return num > 9 || num < 0 ? '' + num : '0' + num
}