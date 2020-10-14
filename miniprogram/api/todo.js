"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var http_1 = require("./http");
var getTodoList = function () {
    return http_1.http.get('/todos?completed=false').then(function (res) {
        if (typeof res.data === "object") {
            return res.data.resources;
        }
        return [];
    });
};
exports.getTodoList = getTodoList;
var createTodoItem = function (description) {
    return http_1.http.post('/todos', { description: description }).then(function (res) {
        return (typeof res.data === "object") ? res.data.resource : [];
    });
};
exports.createTodoItem = createTodoItem;
var deleteTodoItem = function (id) {
    return http_1.http.put("/todos/" + id, { completed: true }).then(function (res) { return res.data; });
};
exports.deleteTodoItem = deleteTodoItem;
var updateTodoItem = function (id, description) {
    return http_1.http.put("/todos/" + id, { completed: false, description: description }).then(function (res) { return (typeof res.data === "object") ? res.data.resource : []; });
};
exports.updateTodoItem = updateTodoItem;
var createTomato = function () {
    return http_1.http.post('/tomatoes').then(function (res) {
        return typeof res.data === 'object' ? res.data.resource : [];
    });
};
exports.createTomato = createTomato;
var updateTomato = function (param) {
    var id = param.id, description = param.description, aborted = param.aborted;
    return http_1.http.put("/tomatoes/" + id, {
        description: description, aborted: aborted
    }).then(function (res) { return typeof res.data === 'object' ? res.data.resource : []; });
};
exports.updateTomato = updateTomato;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidG9kby5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRvZG8udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSwrQkFBOEI7QUFFOUIsSUFBTSxXQUFXLEdBQUc7SUFDbEIsT0FBTyxXQUFJLENBQUMsR0FBRyxDQUFDLHdCQUF3QixDQUFDLENBQUMsSUFBSSxDQUFDLFVBQUMsR0FBRztRQUNqRCxJQUFJLE9BQU8sR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7WUFDaEMsT0FBTyxHQUFHLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQTtTQUMxQjtRQUNELE9BQU8sRUFBRSxDQUFBO0lBQ1gsQ0FBQyxDQUFDLENBQUE7QUFDSixDQUFDLENBQUE7QUFnQ1Esa0NBQVc7QUE5QnBCLElBQU0sY0FBYyxHQUFHLFVBQUMsV0FBbUI7SUFDekMsT0FBTyxXQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxFQUFFLFdBQVcsYUFBQSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBQSxHQUFHO1FBQ2xELE9BQU8sQ0FBQyxPQUFPLEdBQUcsQ0FBQyxJQUFJLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUE7SUFDaEUsQ0FBQyxDQUFDLENBQUE7QUFDSixDQUFDLENBQUE7QUEwQnFCLHdDQUFjO0FBeEJwQyxJQUFNLGNBQWMsR0FBRyxVQUFDLEVBQVU7SUFDaEMsT0FBTyxXQUFJLENBQUMsR0FBRyxDQUFDLFlBQVUsRUFBSSxFQUFFLEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFVBQUMsR0FBRyxJQUFLLE9BQUEsR0FBRyxDQUFDLElBQUksRUFBUixDQUFRLENBQUMsQ0FBQTtBQUM5RSxDQUFDLENBQUE7QUFzQnFDLHdDQUFjO0FBckJwRCxJQUFNLGNBQWMsR0FBRyxVQUFDLEVBQVUsRUFBRSxXQUFtQjtJQUNyRCxPQUFPLFdBQUksQ0FBQyxHQUFHLENBQUMsWUFBVSxFQUFJLEVBQUUsRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLFdBQVcsYUFBQSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBQyxHQUFHLElBQUssT0FBQSxDQUFDLE9BQU8sR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBdkQsQ0FBdUQsQ0FBQyxDQUFBO0FBQzNJLENBQUMsQ0FBQTtBQW1CcUQsd0NBQWM7QUFqQnBFLElBQU0sWUFBWSxHQUFHO0lBQ25CLE9BQU8sV0FBSSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBQyxHQUFHO1FBQ3JDLE9BQU8sT0FBTyxHQUFHLENBQUMsSUFBSSxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQTtJQUM5RCxDQUFDLENBQUMsQ0FBQTtBQUNKLENBQUMsQ0FBQTtBQWFxRSxvQ0FBWTtBQU5sRixJQUFNLFlBQVksR0FBRyxVQUFDLEtBQWdCO0lBQzVCLElBQUEsYUFBRSxFQUFFLCtCQUFXLEVBQUUsdUJBQU8sQ0FBVTtJQUMxQyxPQUFPLFdBQUksQ0FBQyxHQUFHLENBQUMsZUFBYSxFQUFJLEVBQUU7UUFDakMsV0FBVyxhQUFBLEVBQUUsT0FBTyxTQUFBO0tBQ3JCLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBQSxHQUFHLElBQUksT0FBQSxPQUFPLEdBQUcsQ0FBQyxJQUFJLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFyRCxDQUFxRCxDQUFDLENBQUE7QUFDdkUsQ0FBQyxDQUFBO0FBQ21GLG9DQUFZIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgaHR0cCB9IGZyb20gJy4vaHR0cCc7XHJcblxyXG5jb25zdCBnZXRUb2RvTGlzdCA9ICgpID0+IHtcclxuICByZXR1cm4gaHR0cC5nZXQoJy90b2Rvcz9jb21wbGV0ZWQ9ZmFsc2UnKS50aGVuKChyZXMpID0+IHtcclxuICAgIGlmICh0eXBlb2YgcmVzLmRhdGEgPT09IFwib2JqZWN0XCIpIHtcclxuICAgICAgcmV0dXJuIHJlcy5kYXRhLnJlc291cmNlc1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIFtdXHJcbiAgfSlcclxufVxyXG5cclxuY29uc3QgY3JlYXRlVG9kb0l0ZW0gPSAoZGVzY3JpcHRpb246IHN0cmluZykgPT4ge1xyXG4gIHJldHVybiBodHRwLnBvc3QoJy90b2RvcycsIHsgZGVzY3JpcHRpb24gfSkudGhlbihyZXMgPT4ge1xyXG4gICAgcmV0dXJuICh0eXBlb2YgcmVzLmRhdGEgPT09IFwib2JqZWN0XCIpID8gcmVzLmRhdGEucmVzb3VyY2UgOiBbXVxyXG4gIH0pXHJcbn1cclxuXHJcbmNvbnN0IGRlbGV0ZVRvZG9JdGVtID0gKGlkOiBudW1iZXIpID0+IHtcclxuICByZXR1cm4gaHR0cC5wdXQoYC90b2Rvcy8ke2lkfWAsIHsgY29tcGxldGVkOiB0cnVlIH0pLnRoZW4oKHJlcykgPT4gcmVzLmRhdGEpXHJcbn1cclxuY29uc3QgdXBkYXRlVG9kb0l0ZW0gPSAoaWQ6IG51bWJlciwgZGVzY3JpcHRpb246IHN0cmluZykgPT4ge1xyXG4gIHJldHVybiBodHRwLnB1dChgL3RvZG9zLyR7aWR9YCwgeyBjb21wbGV0ZWQ6IGZhbHNlLCBkZXNjcmlwdGlvbiB9KS50aGVuKChyZXMpID0+ICh0eXBlb2YgcmVzLmRhdGEgPT09IFwib2JqZWN0XCIpID8gcmVzLmRhdGEucmVzb3VyY2UgOiBbXSlcclxufVxyXG5cclxuY29uc3QgY3JlYXRlVG9tYXRvID0gKCkgPT4ge1xyXG4gIHJldHVybiBodHRwLnBvc3QoJy90b21hdG9lcycpLnRoZW4oKHJlcykgPT4ge1xyXG4gICAgcmV0dXJuIHR5cGVvZiByZXMuZGF0YSA9PT0gJ29iamVjdCcgPyByZXMuZGF0YS5yZXNvdXJjZSA6IFtdXHJcbiAgfSlcclxufVxyXG5cclxuaW50ZXJmYWNlIFBhcmFtVHlwZSB7XHJcbiAgaWQ6IG51bWJlclxyXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmdcclxuICBhYm9ydGVkOiBib29sZWFuXHJcbn1cclxuY29uc3QgdXBkYXRlVG9tYXRvID0gKHBhcmFtOiBQYXJhbVR5cGUpID0+IHtcclxuICBjb25zdCB7IGlkLCBkZXNjcmlwdGlvbiwgYWJvcnRlZCB9ID0gcGFyYW1cclxuICByZXR1cm4gaHR0cC5wdXQoYC90b21hdG9lcy8ke2lkfWAsIHtcclxuICAgIGRlc2NyaXB0aW9uLCBhYm9ydGVkXHJcbiAgfSkudGhlbihyZXMgPT4gdHlwZW9mIHJlcy5kYXRhID09PSAnb2JqZWN0JyA/IHJlcy5kYXRhLnJlc291cmNlIDogW10pXHJcbn1cclxuZXhwb3J0IHsgZ2V0VG9kb0xpc3QsIGNyZWF0ZVRvZG9JdGVtLCBkZWxldGVUb2RvSXRlbSwgdXBkYXRlVG9kb0l0ZW0sIGNyZWF0ZVRvbWF0bywgdXBkYXRlVG9tYXRvIH0iXX0=