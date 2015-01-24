'use strict';

angular.module('meanTempApp')
  .config(function ($stateProvider) {
    $stateProvider
      .state('benefits', {
        url: '/benefits',
        templateUrl: 'app/benefits/benefits.html',
        controller: 'BenefitsCtrl'
      });
  });