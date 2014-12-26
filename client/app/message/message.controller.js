'use strict';

angular.module('meanTempApp')
  .controller('MessageCtrl', function ($scope, $http, socket) {
    $scope.messages = [];

    $http.get('/api/messages').success(function(awesomeMessages) {
      $scope.awesomeMessages = awesomeMessages;
      socket.syncUpdates('message', $scope.awesomeMessages);
    });

    $scope.addMessage = function() {
      if($scope.newMessage === '') {
        return;
      }
      $http.post('/api/messages', { name: $scope.newMessage.fullname, email: $scope.newMessage.email, message: $scope.newMessage.message });
      $scope.newMessage = '';
    };

    $scope.deleteMessage = function(message) {
      $http.delete('/api/messages/' + message._id);
    };

    $scope.$on('$destroy', function () {
      socket.unsyncUpdates('message');
    });
  });
