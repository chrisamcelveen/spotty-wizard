'use strict';

describe('Controller: BenefitsCtrl', function () {

  // load the controller's module
  beforeEach(module('meanTempApp'));

  var BenefitsCtrl, scope;

  // Initialize the controller and a mock scope
  beforeEach(inject(function ($controller, $rootScope) {
    scope = $rootScope.$new();
    BenefitsCtrl = $controller('BenefitsCtrl', {
      $scope: scope
    });
  }));

  it('should ...', function () {
    expect(1).toEqual(1);
  });
});
