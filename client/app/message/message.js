'use strict';

angular.module('meanTempApp')
  .config(function ($stateProvider) {
    $stateProvider
      .state('message', {
        url: '/message',
        templateUrl: 'app/message/message.html',
        controller: 'MessageCtrl'
      });
  });