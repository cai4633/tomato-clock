var AV = getApp().globalData.AV;
var getTodoList = function () {
    return new AV.Query('Todos').descending('createdAt')
        .find()
        .then(function (todos) {
        return todos.map(function (todo) { return todo.toJSON(); });
    })
        .catch(console.error);
};
var createTodoItem = function (description) {
    var todos = new AV.Object('Todos');
    todos.set('id', Math.random() * 100000 | 0);
    todos.set('completed', false);
    todos.set('description', description);
    return todos.save().then(function (res) { return res.toJSON(); });
};
var deleteTodoItem = function (id) {
    var todo = AV.Object.createWithoutData('Todos', id);
    todo.set('completed', true);
    return todo.save().then(function (res) { return res.toJSON(); });
};
var updateTodoItem = function (id, description) {
    var todo = AV.Object.createWithoutData('Todos', id);
    todo.set('description', description);
    return todo.save().then(function (res) { return res.toJSON(); });
};
var createTomato = function () {
    var tomatoes = new AV.Object('Tomatoes');
    tomatoes.set('id', Math.random() * 100000 | 0);
    tomatoes.set('aborted', false);
    tomatoes.set('description', '');
    return tomatoes.save().then(function (res) { return res.toJSON(); });
};
var updateTomato = function (param) {
    var objectId = param.objectId, description = param.description, aborted = param.aborted;
    var tomato = AV.Object.createWithoutData('Tomatoes', objectId);
    tomato.set('description', description);
    tomato.set('aborted', aborted);
    return tomato.save().then(function (res) { return res.toJSON(); });
};
export { getTodoList, createTodoItem, deleteTodoItem, updateTodoItem, createTomato, updateTomato };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidG9kby5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRvZG8udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBRVEsSUFBQSwyQkFBRSxDQUF3QjtBQUNsQyxJQUFNLFdBQVcsR0FBRztJQUNsQixPQUFPLElBQUksRUFBRSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQyxVQUFVLENBQUMsV0FBVyxDQUFDO1NBQ2pELElBQUksRUFBRTtTQUNOLElBQUksQ0FBQyxVQUFDLEtBQXFCO1FBQzFCLE9BQU8sS0FBSyxDQUFDLEdBQUcsQ0FBQyxVQUFDLElBQUksSUFBSyxPQUFBLElBQUksQ0FBQyxNQUFNLEVBQUUsRUFBYixDQUFhLENBQUMsQ0FBQTtJQUMzQyxDQUFDLENBQUM7U0FDRCxLQUFLLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBQzFCLENBQUMsQ0FBQTtBQUVELElBQU0sY0FBYyxHQUFHLFVBQUMsV0FBbUI7SUFDekMsSUFBTSxLQUFLLEdBQUcsSUFBSSxFQUFFLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFBO0lBQ3BDLEtBQUssQ0FBQyxHQUFHLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxNQUFNLEVBQUUsR0FBRyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUE7SUFDM0MsS0FBSyxDQUFDLEdBQUcsQ0FBQyxXQUFXLEVBQUUsS0FBSyxDQUFDLENBQUE7SUFDN0IsS0FBSyxDQUFDLEdBQUcsQ0FBQyxhQUFhLEVBQUUsV0FBVyxDQUFDLENBQUE7SUFDckMsT0FBTyxLQUFLLENBQUMsSUFBSSxFQUFFLENBQUMsSUFBSSxDQUFDLFVBQUMsR0FBaUIsSUFBSyxPQUFBLEdBQUcsQ0FBQyxNQUFNLEVBQUUsRUFBWixDQUFZLENBQUMsQ0FBQTtBQUMvRCxDQUFDLENBQUE7QUFFRCxJQUFNLGNBQWMsR0FBRyxVQUFDLEVBQVU7SUFDaEMsSUFBTSxJQUFJLEdBQUcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQyxPQUFPLEVBQUUsRUFBRSxDQUFDLENBQUM7SUFDdEQsSUFBSSxDQUFDLEdBQUcsQ0FBQyxXQUFXLEVBQUUsSUFBSSxDQUFDLENBQUM7SUFDNUIsT0FBTyxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUMsSUFBSSxDQUFDLFVBQUMsR0FBaUIsSUFBSyxPQUFBLEdBQUcsQ0FBQyxNQUFNLEVBQUUsRUFBWixDQUFZLENBQUMsQ0FBQztBQUMvRCxDQUFDLENBQUE7QUFDRCxJQUFNLGNBQWMsR0FBRyxVQUFDLEVBQVUsRUFBRSxXQUFtQjtJQUNyRCxJQUFNLElBQUksR0FBRyxFQUFFLENBQUMsTUFBTSxDQUFDLGlCQUFpQixDQUFDLE9BQU8sRUFBRSxFQUFFLENBQUMsQ0FBQztJQUN0RCxJQUFJLENBQUMsR0FBRyxDQUFDLGFBQWEsRUFBRSxXQUFXLENBQUMsQ0FBQztJQUNyQyxPQUFPLElBQUksQ0FBQyxJQUFJLEVBQUUsQ0FBQyxJQUFJLENBQUMsVUFBQyxHQUFpQixJQUFLLE9BQUEsR0FBRyxDQUFDLE1BQU0sRUFBRSxFQUFaLENBQVksQ0FBQyxDQUFDO0FBQy9ELENBQUMsQ0FBQTtBQUVELElBQU0sWUFBWSxHQUFHO0lBQ25CLElBQU0sUUFBUSxHQUFHLElBQUksRUFBRSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQTtJQUMxQyxRQUFRLENBQUMsR0FBRyxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsTUFBTSxFQUFFLEdBQUcsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFBO0lBQzlDLFFBQVEsQ0FBQyxHQUFHLENBQUMsU0FBUyxFQUFFLEtBQUssQ0FBQyxDQUFBO0lBQzlCLFFBQVEsQ0FBQyxHQUFHLENBQUMsYUFBYSxFQUFFLEVBQUUsQ0FBQyxDQUFBO0lBQy9CLE9BQU8sUUFBUSxDQUFDLElBQUksRUFBRSxDQUFDLElBQUksQ0FBQyxVQUFDLEdBQWUsSUFBSyxPQUFBLEdBQUcsQ0FBQyxNQUFNLEVBQUUsRUFBWixDQUFZLENBQUMsQ0FBQTtBQUNoRSxDQUFDLENBQUE7QUFRRCxJQUFNLFlBQVksR0FBRyxVQUFDLEtBQWdCO0lBQzVCLElBQUEseUJBQVEsRUFBRSwrQkFBVyxFQUFFLHVCQUFPLENBQVU7SUFDaEQsSUFBTSxNQUFNLEdBQUcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQyxVQUFVLEVBQUUsUUFBUSxDQUFDLENBQUM7SUFDakUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxhQUFhLEVBQUUsV0FBVyxDQUFDLENBQUM7SUFDdkMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUE7SUFDOUIsT0FBTyxNQUFNLENBQUMsSUFBSSxFQUFFLENBQUMsSUFBSSxDQUFDLFVBQUMsR0FBZSxJQUFLLE9BQUEsR0FBRyxDQUFDLE1BQU0sRUFBRSxFQUFaLENBQVksQ0FBQyxDQUFDO0FBQy9ELENBQUMsQ0FBQTtBQUNELE9BQU8sRUFBRSxXQUFXLEVBQUUsY0FBYyxFQUFFLGNBQWMsRUFBRSxjQUFjLEVBQUUsWUFBWSxFQUFFLFlBQVksRUFBRSxDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgVG9kb0xpc3RJdGVtLCBUb21hdG9JdGVtIH0gZnJvbSAnLi4vLi4vdHlwaW5ncy90eXBlcy9pbmRleCc7XHJcblxyXG5jb25zdCB7IEFWIH0gPSBnZXRBcHAoKS5nbG9iYWxEYXRhXHJcbmNvbnN0IGdldFRvZG9MaXN0ID0gKCkgPT4ge1xyXG4gIHJldHVybiBuZXcgQVYuUXVlcnkoJ1RvZG9zJykuZGVzY2VuZGluZygnY3JlYXRlZEF0JylcclxuICAgIC5maW5kKClcclxuICAgIC50aGVuKCh0b2RvczogVG9kb0xpc3RJdGVtW10pID0+IHtcclxuICAgICAgcmV0dXJuIHRvZG9zLm1hcCgodG9kbykgPT4gdG9kby50b0pTT04oKSlcclxuICAgIH0pXHJcbiAgICAuY2F0Y2goY29uc29sZS5lcnJvcik7XHJcbn1cclxuXHJcbmNvbnN0IGNyZWF0ZVRvZG9JdGVtID0gKGRlc2NyaXB0aW9uOiBzdHJpbmcpID0+IHtcclxuICBjb25zdCB0b2RvcyA9IG5ldyBBVi5PYmplY3QoJ1RvZG9zJylcclxuICB0b2Rvcy5zZXQoJ2lkJywgTWF0aC5yYW5kb20oKSAqIDEwMDAwMCB8IDApXHJcbiAgdG9kb3Muc2V0KCdjb21wbGV0ZWQnLCBmYWxzZSlcclxuICB0b2Rvcy5zZXQoJ2Rlc2NyaXB0aW9uJywgZGVzY3JpcHRpb24pXHJcbiAgcmV0dXJuIHRvZG9zLnNhdmUoKS50aGVuKChyZXM6IFRvZG9MaXN0SXRlbSkgPT4gcmVzLnRvSlNPTigpKVxyXG59XHJcblxyXG5jb25zdCBkZWxldGVUb2RvSXRlbSA9IChpZDogc3RyaW5nKSA9PiB7XHJcbiAgY29uc3QgdG9kbyA9IEFWLk9iamVjdC5jcmVhdGVXaXRob3V0RGF0YSgnVG9kb3MnLCBpZCk7XHJcbiAgdG9kby5zZXQoJ2NvbXBsZXRlZCcsIHRydWUpO1xyXG4gIHJldHVybiB0b2RvLnNhdmUoKS50aGVuKChyZXM6IFRvZG9MaXN0SXRlbSkgPT4gcmVzLnRvSlNPTigpKTtcclxufVxyXG5jb25zdCB1cGRhdGVUb2RvSXRlbSA9IChpZDogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nKSA9PiB7XHJcbiAgY29uc3QgdG9kbyA9IEFWLk9iamVjdC5jcmVhdGVXaXRob3V0RGF0YSgnVG9kb3MnLCBpZCk7XHJcbiAgdG9kby5zZXQoJ2Rlc2NyaXB0aW9uJywgZGVzY3JpcHRpb24pO1xyXG4gIHJldHVybiB0b2RvLnNhdmUoKS50aGVuKChyZXM6IFRvZG9MaXN0SXRlbSkgPT4gcmVzLnRvSlNPTigpKTtcclxufVxyXG5cclxuY29uc3QgY3JlYXRlVG9tYXRvID0gKCkgPT4ge1xyXG4gIGNvbnN0IHRvbWF0b2VzID0gbmV3IEFWLk9iamVjdCgnVG9tYXRvZXMnKVxyXG4gIHRvbWF0b2VzLnNldCgnaWQnLCBNYXRoLnJhbmRvbSgpICogMTAwMDAwIHwgMClcclxuICB0b21hdG9lcy5zZXQoJ2Fib3J0ZWQnLCBmYWxzZSlcclxuICB0b21hdG9lcy5zZXQoJ2Rlc2NyaXB0aW9uJywgJycpXHJcbiAgcmV0dXJuIHRvbWF0b2VzLnNhdmUoKS50aGVuKChyZXM6IFRvbWF0b0l0ZW0pID0+IHJlcy50b0pTT04oKSlcclxufVxyXG5cclxuaW50ZXJmYWNlIFBhcmFtVHlwZSB7XHJcbiAgb2JqZWN0SWQ6IHN0cmluZ1xyXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmdcclxuICBhYm9ydGVkOiBib29sZWFuXHJcbn1cclxuXHJcbmNvbnN0IHVwZGF0ZVRvbWF0byA9IChwYXJhbTogUGFyYW1UeXBlKSA9PiB7XHJcbiAgY29uc3QgeyBvYmplY3RJZCwgZGVzY3JpcHRpb24sIGFib3J0ZWQgfSA9IHBhcmFtXHJcbiAgY29uc3QgdG9tYXRvID0gQVYuT2JqZWN0LmNyZWF0ZVdpdGhvdXREYXRhKCdUb21hdG9lcycsIG9iamVjdElkKTtcclxuICB0b21hdG8uc2V0KCdkZXNjcmlwdGlvbicsIGRlc2NyaXB0aW9uKTtcclxuICB0b21hdG8uc2V0KCdhYm9ydGVkJywgYWJvcnRlZClcclxuICByZXR1cm4gdG9tYXRvLnNhdmUoKS50aGVuKChyZXM6IFRvbWF0b0l0ZW0pID0+IHJlcy50b0pTT04oKSk7XHJcbn1cclxuZXhwb3J0IHsgZ2V0VG9kb0xpc3QsIGNyZWF0ZVRvZG9JdGVtLCBkZWxldGVUb2RvSXRlbSwgdXBkYXRlVG9kb0l0ZW0sIGNyZWF0ZVRvbWF0bywgdXBkYXRlVG9tYXRvIH0iXX0=