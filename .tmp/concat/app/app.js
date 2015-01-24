'use strict';

angular.module('meanTempApp', [
  'ngCookies',
  'ngResource',
  'ngSanitize',
  'btford.socket-io',
  'ui.router',
  'ui.bootstrap'
])
  .config(["$stateProvider", "$urlRouterProvider", "$locationProvider", "$httpProvider", function ($stateProvider, $urlRouterProvider, $locationProvider, $httpProvider) {
    $urlRouterProvider
      .otherwise('/');

    $locationProvider.html5Mode(true);
    $httpProvider.interceptors.push('authInterceptor');
  }])

  .factory('authInterceptor', ["$rootScope", "$q", "$cookieStore", "$location", function ($rootScope, $q, $cookieStore, $location) {
    return {
      // Add authorization token to headers
      request: function (config) {
        config.headers = config.headers || {};
        if ($cookieStore.get('token')) {
          config.headers.Authorization = 'Bearer ' + $cookieStore.get('token');
        }
        return config;
      },

      // Intercept 401s and redirect you to login
      responseError: function(response) {
        if(response.status === 401) {
          $location.path('/login');
          // remove any stale tokens
          $cookieStore.remove('token');
          return $q.reject(response);
        }
        else {
          return $q.reject(response);
        }
      }
    };
  }])

  .run(["$rootScope", "$location", "Auth", function ($rootScope, $location, Auth) {
    // Redirect to login if route requires auth and you're not logged in
    $rootScope.$on('$stateChangeStart', function (event, next) {
      Auth.isLoggedInAsync(function(loggedIn) {
        if (next.authenticate && !loggedIn) {
          $location.path('/login');
        }
      });
    });
  }]);
'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('login', {
        url: '/login',
        templateUrl: 'app/account/login/login.html',
        controller: 'LoginCtrl'
      })
      .state('signup', {
        url: '/signup',
        templateUrl: 'app/account/signup/signup.html',
        controller: 'SignupCtrl'
      })
      .state('settings', {
        url: '/settings',
        templateUrl: 'app/account/settings/settings.html',
        controller: 'SettingsCtrl',
        authenticate: true
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .controller('LoginCtrl', ["$scope", "Auth", "$location", "$window", function ($scope, Auth, $location, $window) {
    $scope.user = {};
    $scope.errors = {};

    $scope.login = function(form) {
      $scope.submitted = true;

      if(form.$valid) {
        Auth.login({
          email: $scope.user.email,
          password: $scope.user.password
        })
        .then( function() {
          // Logged in, redirect to home
          $location.path('/');
        })
        .catch( function(err) {
          $scope.errors.other = err.message;
        });
      }
    };

    $scope.loginOauth = function(provider) {
      $window.location.href = '/auth/' + provider;
    };
  }]);

'use strict';

angular.module('meanTempApp')
  .controller('SettingsCtrl', ["$scope", "User", "Auth", function ($scope, User, Auth) {
    $scope.errors = {};

    $scope.changePassword = function(form) {
      $scope.submitted = true;
      if(form.$valid) {
        Auth.changePassword( $scope.user.oldPassword, $scope.user.newPassword )
        .then( function() {
          $scope.message = 'Password successfully changed.';
        })
        .catch( function() {
          form.password.$setValidity('mongoose', false);
          $scope.errors.other = 'Incorrect password';
          $scope.message = '';
        });
      }
		};
  }]);

'use strict';

angular.module('meanTempApp')
  .controller('SignupCtrl', ["$scope", "Auth", "$location", "$window", function ($scope, Auth, $location, $window) {
    $scope.user = {};
    $scope.errors = {};

    $scope.register = function(form) {
      $scope.submitted = true;

      if(form.$valid) {
        Auth.createUser({
          name: $scope.user.name,
          email: $scope.user.email,
          password: $scope.user.password
        })
        .then( function() {
          // Account created, redirect to home
          $location.path('/');
        })
        .catch( function(err) {
          err = err.data;
          $scope.errors = {};

          // Update validity of form fields that match the mongoose errors
          angular.forEach(err.errors, function(error, field) {
            form[field].$setValidity('mongoose', false);
            $scope.errors[field] = error.message;
          });
        });
      }
    };

    $scope.loginOauth = function(provider) {
      $window.location.href = '/auth/' + provider;
    };
  }]);

'use strict';

angular.module('meanTempApp')
  .controller('AdminCtrl', ["$scope", "$http", "Auth", "User", function ($scope, $http, Auth, User) {

    // Use the User $resource to fetch all users
    $scope.users = User.query();

    $scope.delete = function(user) {
      User.remove({ id: user._id });
      angular.forEach($scope.users, function(u, i) {
        if (u === user) {
          $scope.users.splice(i, 1);
        }
      });
    };
  }]);

'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('admin', {
        url: '/admin',
        templateUrl: 'app/admin/admin.html',
        controller: 'AdminCtrl'
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .controller('BenefitsCtrl', ["$scope", function ($scope) {
    $scope.message = 'Hello';
  }]);

'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('benefits', {
        url: '/benefits',
        templateUrl: 'app/benefits/benefits.html',
        controller: 'BenefitsCtrl'
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .controller('FaqCtrl', ["$scope", function ($scope) {
    $scope.message = 'Hello';
  }]);

'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('faq', {
        url: '/faq',
        templateUrl: 'app/faq/faq.html',
        controller: 'FaqCtrl'
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .controller('MainCtrl', ["$scope", "$http", "socket", function ($scope, $http, socket) {
    $scope.awesomeThings = [];

    $http.get('/api/things').success(function(awesomeThings) {
      $scope.awesomeThings = awesomeThings;
      socket.syncUpdates('thing', $scope.awesomeThings);
    });

    $scope.addThing = function() {
      if($scope.newThing === '') {
        return;
      }
      $http.post('/api/things', { name: $scope.newThing });
      $scope.newThing = '';
    };

    $scope.deleteThing = function(thing) {
      $http.delete('/api/things/' + thing._id);
    };

    $scope.$on('$destroy', function () {
      socket.unsyncUpdates('thing');
    });

    $scope.me = "This is a joke";
  }]);

'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('main', {
        url: '/',
        templateUrl: 'app/main/main.html',
        controller: 'MainCtrl'
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .controller('MessageCtrl', ["$scope", "$http", "socket", function ($scope, $http, socket) {
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
  }]);

'use strict';

angular.module('meanTempApp')
  .config(["$stateProvider", function ($stateProvider) {
    $stateProvider
      .state('message', {
        url: '/message',
        templateUrl: 'app/message/message.html',
        controller: 'MessageCtrl'
      });
  }]);
'use strict';

angular.module('meanTempApp')
  .factory('Auth', ["$location", "$rootScope", "$http", "User", "$cookieStore", "$q", function Auth($location, $rootScope, $http, User, $cookieStore, $q) {
    var currentUser = {};
    if($cookieStore.get('token')) {
      currentUser = User.get();
    }

    return {

      /**
       * Authenticate user and save token
       *
       * @param  {Object}   user     - login info
       * @param  {Function} callback - optional
       * @return {Promise}
       */
      login: function(user, callback) {
        var cb = callback || angular.noop;
        var deferred = $q.defer();

        $http.post('/auth/local', {
          email: user.email,
          password: user.password
        }).
        success(function(data) {
          $cookieStore.put('token', data.token);
          currentUser = User.get();
          deferred.resolve(data);
          return cb();
        }).
        error(function(err) {
          this.logout();
          deferred.reject(err);
          return cb(err);
        }.bind(this));

        return deferred.promise;
      },

      /**
       * Delete access token and user info
       *
       * @param  {Function}
       */
      logout: function() {
        $cookieStore.remove('token');
        currentUser = {};
      },

      /**
       * Create a new user
       *
       * @param  {Object}   user     - user info
       * @param  {Function} callback - optional
       * @return {Promise}
       */
      createUser: function(user, callback) {
        var cb = callback || angular.noop;

        return User.save(user,
          function(data) {
            $cookieStore.put('token', data.token);
            currentUser = User.get();
            return cb(user);
          },
          function(err) {
            this.logout();
            return cb(err);
          }.bind(this)).$promise;
      },

      /**
       * Change password
       *
       * @param  {String}   oldPassword
       * @param  {String}   newPassword
       * @param  {Function} callback    - optional
       * @return {Promise}
       */
      changePassword: function(oldPassword, newPassword, callback) {
        var cb = callback || angular.noop;

        return User.changePassword({ id: currentUser._id }, {
          oldPassword: oldPassword,
          newPassword: newPassword
        }, function(user) {
          return cb(user);
        }, function(err) {
          return cb(err);
        }).$promise;
      },

      /**
       * Gets all available info on authenticated user
       *
       * @return {Object} user
       */
      getCurrentUser: function() {
        return currentUser;
      },

      /**
       * Check if a user is logged in
       *
       * @return {Boolean}
       */
      isLoggedIn: function() {
        return currentUser.hasOwnProperty('role');
      },

      /**
       * Waits for currentUser to resolve before checking if user is logged in
       */
      isLoggedInAsync: function(cb) {
        if(currentUser.hasOwnProperty('$promise')) {
          currentUser.$promise.then(function() {
            cb(true);
          }).catch(function() {
            cb(false);
          });
        } else if(currentUser.hasOwnProperty('role')) {
          cb(true);
        } else {
          cb(false);
        }
      },

      /**
       * Check if a user is an admin
       *
       * @return {Boolean}
       */
      isAdmin: function() {
        return currentUser.role === 'admin';
      },

      /**
       * Get auth token
       */
      getToken: function() {
        return $cookieStore.get('token');
      }
    };
  }]);

'use strict';

angular.module('meanTempApp')
  .factory('User', ["$resource", function ($resource) {
    return $resource('/api/users/:id/:controller', {
      id: '@_id'
    },
    {
      changePassword: {
        method: 'PUT',
        params: {
          controller:'password'
        }
      },
      get: {
        method: 'GET',
        params: {
          id:'me'
        }
      }
	  });
  }]);

'use strict';

angular.module('meanTempApp')
  .factory('Modal', ["$rootScope", "$modal", function ($rootScope, $modal) {
    /**
     * Opens a modal
     * @param  {Object} scope      - an object to be merged with modal's scope
     * @param  {String} modalClass - (optional) class(es) to be applied to the modal
     * @return {Object}            - the instance $modal.open() returns
     */
    function openModal(scope, modalClass) {
      var modalScope = $rootScope.$new();
      scope = scope || {};
      modalClass = modalClass || 'modal-default';

      angular.extend(modalScope, scope);

      return $modal.open({
        templateUrl: 'components/modal/modal.html',
        windowClass: modalClass,
        scope: modalScope
      });
    }

    // Public API here
    return {

      /* Confirmation modals */
      confirm: {

        /**
         * Create a function to open a delete confirmation modal (ex. ng-click='myModalFn(name, arg1, arg2...)')
         * @param  {Function} del - callback, ran when delete is confirmed
         * @return {Function}     - the function to open the modal (ex. myModalFn)
         */
        delete: function(del) {
          del = del || angular.noop;

          /**
           * Open a delete confirmation modal
           * @param  {String} name   - name or info to show on modal
           * @param  {All}           - any additional args are passed staight to del callback
           */
          return function() {
            var args = Array.prototype.slice.call(arguments),
                name = args.shift(),
                deleteModal;

            deleteModal = openModal({
              modal: {
                dismissable: true,
                title: 'Confirm Delete',
                html: '<p>Are you sure you want to delete <strong>' + name + '</strong> ?</p>',
                buttons: [{
                  classes: 'btn-danger',
                  text: 'Delete',
                  click: function(e) {
                    deleteModal.close(e);
                  }
                }, {
                  classes: 'btn-default',
                  text: 'Cancel',
                  click: function(e) {
                    deleteModal.dismiss(e);
                  }
                }]
              }
            }, 'modal-danger');

            deleteModal.result.then(function(event) {
              del.apply(event, args);
            });
          };
        }
      }
    };
  }]);

'use strict';

/**
 * Removes server error when user updates input
 */
angular.module('meanTempApp')
  .directive('mongooseError', function () {
    return {
      restrict: 'A',
      require: 'ngModel',
      link: function(scope, element, attrs, ngModel) {
        element.on('keydown', function() {
          return ngModel.$setValidity('mongoose', true);
        });
      }
    };
  });
'use strict';

angular.module('meanTempApp')
  .controller('NavbarCtrl', ["$scope", "$location", "Auth", function ($scope, $location, Auth) {
    $scope.menu = [{
      'title': 'Benefits',
      'link': '/benefits'
    },{
      'title': 'Our Technology',
      'link': '/faq'
    },

    ];

    $scope.isCollapsed = true;
    $scope.isLoggedIn = Auth.isLoggedIn;
    $scope.isAdmin = Auth.isAdmin;
    $scope.getCurrentUser = Auth.getCurrentUser;

    $scope.logout = function() {
      Auth.logout();
      $location.path('/login');
    };

    $scope.isActive = function(route) {
      return route === $location.path();
    };
  }]);
/* global io */
'use strict';

angular.module('meanTempApp')
  .factory('socket', ["socketFactory", function(socketFactory) {

    // socket.io now auto-configures its connection when we ommit a connection url
    var ioSocket = io('', {
      // Send auth token on connection, you will need to DI the Auth service above
      // 'query': 'token=' + Auth.getToken()
      path: '/socket.io-client'
    });

    var socket = socketFactory({
      ioSocket: ioSocket
    });

    return {
      socket: socket,

      /**
       * Register listeners to sync an array with updates on a model
       *
       * Takes the array we want to sync, the model name that socket updates are sent from,
       * and an optional callback function after new items are updated.
       *
       * @param {String} modelName
       * @param {Array} array
       * @param {Function} cb
       */
      syncUpdates: function (modelName, array, cb) {
        cb = cb || angular.noop;

        /**
         * Syncs item creation/updates on 'model:save'
         */
        socket.on(modelName + ':save', function (item) {
          var oldItem = _.find(array, {_id: item._id});
          var index = array.indexOf(oldItem);
          var event = 'created';

          // replace oldItem if it exists
          // otherwise just add item to the collection
          if (oldItem) {
            array.splice(index, 1, item);
            event = 'updated';
          } else {
            array.push(item);
          }

          cb(event, item, array);
        });

        /**
         * Syncs removed items on 'model:remove'
         */
        socket.on(modelName + ':remove', function (item) {
          var event = 'deleted';
          _.remove(array, {_id: item._id});
          cb(event, item, array);
        });
      },

      /**
       * Removes listeners for a models updates on the socket
       *
       * @param modelName
       */
      unsyncUpdates: function (modelName) {
        socket.removeAllListeners(modelName + ':save');
        socket.removeAllListeners(modelName + ':remove');
      }
    };
  }]);

angular.module('meanTempApp').run(['$templateCache', function($templateCache) {
  'use strict';

  $templateCache.put('app/account/login/login.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><div class=container><div class=row><div class=col-sm-12><h1>Login</h1><p>Accounts are reset on server restart from <code>server/config/seed.js</code>. Default account is <code>test@test.com</code> / <code>test</code></p><p>Admin account is <code>admin@admin.com</code> / <code>admin</code></p></div><div class=col-sm-12><form class=form name=form ng-submit=login(form) novalidate><div class=form-group><label>Email</label><input type=email name=email class=form-control ng-model=user.email required></div><div class=form-group><label>Password</label><input type=password name=password class=form-control ng-model=user.password required></div><div class=\"form-group has-error\"><p class=help-block ng-show=\"form.email.$error.required && form.password.$error.required && submitted\">Please enter your email and password.</p><p class=help-block ng-show=\"form.email.$error.email && submitted\">Please enter a valid email.</p><p class=help-block>{{ errors.other }}</p></div><div><button class=\"btn btn-inverse btn-lg btn-login\" type=submit>Login</button> <a class=\"btn btn-default btn-lg btn-register\" href=/signup>Register</a></div><hr><div><a class=\"btn btn-google-plus\" href=\"\" ng-click=\"loginOauth('google')\"><i class=\"fa fa-google-plus\"></i> Connect with Google+</a></div></form></div></div><hr></div>"
  );


  $templateCache.put('app/account/settings/settings.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><div class=container><div class=row><div class=col-sm-12><h1>Change Password</h1></div><div class=col-sm-12><form class=form name=form ng-submit=changePassword(form) novalidate><div class=form-group><label>Current Password</label><input type=password name=password class=form-control ng-model=user.oldPassword mongoose-error><p class=help-block ng-show=form.password.$error.mongoose>{{ errors.other }}</p></div><div class=form-group><label>New Password</label><input type=password name=newPassword class=form-control ng-model=user.newPassword ng-minlength=3 required><p class=help-block ng-show=\"(form.newPassword.$error.minlength || form.newPassword.$error.required) && (form.newPassword.$dirty || submitted)\">Password must be at least 3 characters.</p></div><p class=help-block>{{ message }}</p><button class=\"btn btn-lg btn-primary\" type=submit>Save changes</button></form></div></div></div>"
  );


  $templateCache.put('app/account/signup/signup.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><div class=container><div class=row><div class=col-sm-12><h1>Sign up</h1></div><div class=col-sm-12><form class=form name=form ng-submit=register(form) novalidate><div class=form-group ng-class=\"{ 'has-success': form.name.$valid && submitted,\n" +
    "                                            'has-error': form.name.$invalid && submitted }\"><label>Name</label><input name=name class=form-control ng-model=user.name required><p class=help-block ng-show=\"form.name.$error.required && submitted\">A name is required</p></div><div class=form-group ng-class=\"{ 'has-success': form.email.$valid && submitted,\n" +
    "                                            'has-error': form.email.$invalid && submitted }\"><label>Email</label><input type=email name=email class=form-control ng-model=user.email required mongoose-error><p class=help-block ng-show=\"form.email.$error.email && submitted\">Doesn't look like a valid email.</p><p class=help-block ng-show=\"form.email.$error.required && submitted\">What's your email address?</p><p class=help-block ng-show=form.email.$error.mongoose>{{ errors.email }}</p></div><div class=form-group ng-class=\"{ 'has-success': form.password.$valid && submitted,\n" +
    "                                            'has-error': form.password.$invalid && submitted }\"><label>Password</label><input type=password name=password class=form-control ng-model=user.password ng-minlength=3 required mongoose-error><p class=help-block ng-show=\"(form.password.$error.minlength || form.password.$error.required) && submitted\">Password must be at least 3 characters.</p><p class=help-block ng-show=form.password.$error.mongoose>{{ errors.password }}</p></div><div><button class=\"btn btn-inverse btn-lg btn-login\" type=submit>Sign up</button> <a class=\"btn btn-default btn-lg btn-register\" href=/login>Login</a></div><hr><div><a class=\"btn btn-google-plus\" href=\"\" ng-click=\"loginOauth('google')\"><i class=\"fa fa-google-plus\"></i> Connect with Google+</a></div></form></div></div><hr></div>"
  );


  $templateCache.put('app/admin/admin.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><div class=container><p>The delete user and user index api routes are restricted to users with the 'admin' role.</p><ul class=list-group><li class=list-group-item ng-repeat=\"user in users\"><strong>{{user.name}}</strong><br><span class=text-muted>{{user.email}}</span> <a ng-click=delete(user) class=trash><span class=\"glyphicon glyphicon-trash pull-right\"></span></a></li></ul></div>"
  );


  $templateCache.put('app/benefits/benefits.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><section id=detail class=detail><div class=container><div class=col-md-12><div class=\"row margin-60\"><h1 class=\"text-center blue\">Benefits</h1></div><div class=\"row margin-40\"><div class=\"icon col-md-4 col-md-offset-1\"><span class=\"fa fa-map-marker fa-5x\"></span></div><div class=col-md-8><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div></div><div class=\"container-fluid margin-40\"><div class=\"col-md-10 col-md-offset-1\"><div class=row><hr class=the-margin></div></div></div><div class=\"row margin-40\"><div class=\"col-md-8 col-md-offset-1\"><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div><div class=\"icon col-md-4\"><span class=\"fa fa-gear fa-5x\"></span></div></div><div class=\"container-fluid margin-40\"><div class=\"col-md-10 col-md-offset-1\"><div class=row><hr class=the-margin></div></div></div><div class=\"row margin-40\"><div class=\"icon col-md-4 col-md-offset-1\"><span class=\"fa fa-tablet fa-5x\"></span></div><div class=col-md-8><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div></div></div></div></section><footer class=footer><div class=container><p>Spotwise &copy; 2014</p></div></footer>"
  );


  $templateCache.put('app/faq/faq.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><section id=detail class=detail><div class=container><div class=col-md-12><div class=\"row margin-60\"><h1 class=\"text-center blue\">Benefits</h1></div><div class=\"row margin-40\"><div class=\"icon col-md-4 col-md-offset-1\"><span class=\"fa fa-map-marker fa-5x\"></span></div><div class=col-md-8><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div></div><div class=\"container-fluid margin-40\"><div class=\"col-md-10 col-md-offset-1\"><div class=row><hr class=the-margin></div></div></div><div class=\"row margin-40\"><div class=\"col-md-8 col-md-offset-1\"><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div><div class=\"icon col-md-4\"><span class=\"fa fa-gear fa-5x\"></span></div></div><div class=\"container-fluid margin-40\"><div class=\"col-md-10 col-md-offset-1\"><div class=row><hr class=the-margin></div></div></div><div class=\"row margin-40\"><div class=\"icon col-md-4 col-md-offset-1\"><span class=\"fa fa-tablet fa-5x\"></span></div><div class=col-md-8><p class=wrap><span class=\"emphasis blue\">Lorem ipsum</span> dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus.</p></div></div></div></div></section><footer class=footer><div class=container><p>Spotwise &copy; 2014</p></div></footer>"
  );


  $templateCache.put('app/main/main.html',
    "<div ng-include=\"'components/navbar/navbar.html'\"></div><header id=header class=header><div class=container><div class=row><div class=\"col-md-10 col-md-offset-1\"><div class=\"row header-box\"><div class=\"col-md-6 intro-message box animated fadeIn delay2\"><h1 class=margin-20>Real-Time Parking Analytics</h1><p class=margin-10>Maximize your bottom line with smart enforcement routing and dynamic pricing</p><div class=\"col-md-10 col-md-offset-1 text-center animated fadeIn delay2\"><a id=button-blue class=\"btn-blue-animate btn-text-transparent\" href=#>Contact Us Now</a></div></div><div class=\"col-md-6 hidden-xs text-center\"><div class=\"iphone-container animated fadeInDown\"><img src=assets/images/iphone.png class=img-responsive alt=...><div class=iphone-screen><div id=screen-slider class=\"carousel slide absolute\" data-ride=carousel><div class=\"carousel-inner absolute\"><div class=\"item active absolute\"><img src=assets/images/map-screen.png alt=...></div><div class=\"item absolute\"><img src=assets/images/slider-comments.png alt=...></div></div></div></div><!-- / screen slider --></div><!-- / iphone container --></div></div></div></div></div><!-- /.container --></header><!-- /.intro-header --><!-- Services Section --><section id=services class=services><div class=container><div class=row><div class=col-md-4><div class=services-box><div class=icon><span class=\"fa fa-map-marker fa-5x\"></span></div><h3>Manages Services</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec.</p></div></div><div class=col-md-4><div class=services-box><div class=icon><span class=\"fa fa-gear fa-5x\"></span></div><h3>Manages Services</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec.</p></div></div><div class=col-md-4><div class=services-box><div class=icon><span class=\"fa fa-tablet fa-5x\"></span></div><h3>Manages Services</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec.</p></div></div></div></div></section><!-- End Services Section --><!--\n" +
    "\n" +
    "  <section id=\"quote\" class=\"quote\">\n" +
    "    <div class=\"container\">\n" +
    "      <div class=\"row\">\n" +
    "        <div class=\"col-md-10 col-md-offset-1\">\n" +
    "          <p class=\"text-center blue\"><span class=\"fa fa-quote-left\"></span>&nbsp;SpotWise is the dopest thing I've ever seen!&nbsp;<span class=\"fa fa-quote-right\"></span></p>\n" +
    "        </div>\n" +
    "      </div>\n" +
    "    </div>\n" +
    "  </section>\n" +
    "\n" +
    "--><div class=\"container-fluid margin-40\"><div class=\"col-md-10 col-md-offset-1\"><div class=row><hr class=the-margin></div></div></div><section id=faq class=faq><div class=container><div class=row><img src=assets/images/spot-info.png class=\"img-responsive img-rounded\"></div></div></section><section id=sponsors class=sponsors><div class=container-fluid><div class=\"col-md-8 col-md-offset-2\"><div class=row><div class=\"col-md-12 header-sub\"><h2 class=\"text-center blue margin-40\">Our Sponsors and Partners</h2></div></div><div class=row><div class=col-md-12><ul><li class=col-md-2><img class=img-responsive src=\"../images/logos-maponics.png\"></li><li class=col-md-2><img class=img-responsive src=\"../images/logos-coral_gables_coc.png\"></li><li class=col-md-2><img class=img-responsive src=\"../images/logos-spotcrime.png\"></li><li class=col-md-2><img class=img-responsive src=\"../images/logos-us_census.png\"></li><li class=col-md-2><img class=img-responsive src=\"../images/logos-apa.png\"></li><li class=col-md-2><img class=img-responsive src=\"../images/logos-urban_land_institute.png\"></li></ul></div></div></div></div></section><!-- About Section --><section id=about class=about><div class=container><div class=\"row margin-60\"><div class=col-md-12><div class=title-page><h2 class=title>About SpotWise</h2><h3 class=title-description>Our Team &amp; Culture.</h3><div class=page-description><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam sed ligula odio. Sed id metus felis. Ut pretium nisl non justo condimentum id tincidunt nunc faucibus. Ut neque eros, pulvinar eu blandit quis, lacinia nec ipsum. Etiam vel orci ipsum. Sed eget velit ipsum. Duis in tortor scelerisque felis mattis imperdiet. Donec at libero tellus. <a href=#>Suspendisse consectetur</a> consectetur bibendum. Pellentesque posuere, ligula volutpat elementum interdum, diam arcu elementum ipsum, vel ultricies est mauris ut nisi.</p></div></div></div></div><div class=row><div class=\"col-md-4 profile\"><div class=image-wrap><div class=hover-wrap><span class=overlay-img></span> <span class=overlay-text-thumb>CEO/Founder</span></div><img src=assets/images/james.png alt=\"James Crater\"></div><h3 class=profile-name>James Crater</h3><p class=profile-description>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas ac augue at erat <a href=#>hendrerit dictum</a>. Praesent porta, purus eget sagittis imperdiet, nulla mi ullamcorper metus, id hendrerit metus diam vitae est. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.</p></div><div class=\"col-md-4 profile\"><div class=image-wrap><div class=hover-wrap><span class=overlay-img></span> <span class=overlay-text-thumb>COO/Founder</span></div><img src=assets/images/chase.png alt=\"Chase Merlin\"></div><h3 class=profile-name>Chase Merlin</h3><p class=profile-description>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas ac augue at erat <a href=#>hendrerit dictum</a>. Praesent porta, purus eget sagittis imperdiet, nulla mi ullamcorper metus, id hendrerit metus diam vitae est. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.</p></div><div class=\"col-md-4 profile\"><div class=image-wrap><div class=hover-wrap><span class=overlay-img></span> <span class=overlay-text-thumb>CTO/Founder</span></div><img src=assets/images/zach.png alt=\"Zack McCormick\"></div><h3 class=profile-name>Zach McCormick</h3><p class=profile-description>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas ac augue at erat <a href=#>hendrerit dictum</a>. Praesent porta, purus eget sagittis imperdiet, nulla mi ullamcorper metus, id hendrerit metus diam vitae est. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.</p></div></div></div></section><!-- End About Section --><!-- Contact Section --><section id=contact-form class=contact-form><div class=container><div class=row><div class=col-md-9><form id=form role=form><div class=form-group><input type=password class=form-control id=exampleInputName placeholder=Name></div><div class=form-group><input type=email class=form-control id=exampleInputEmail1 placeholder=Email></div><div class=form-group><textarea type=password class=form-control id=exampleInputMessage placeholder=Message></textarea></div></form></div><div class=\"col-md-3 contact-details\"><h2 class=\"text-center white margin-20\">Inquire</h2><ul><li><p class=\"text-center white\"><span class=\"fa fa-envelope fa-1x\"></span> &nbsp; info@spotwise.co</p></li><li><p class=\"text-center white\"><span class=\"fa fa-phone fa-1x\"></span> &nbsp; 1 (813) 716-7850</p></li><li><p class=\"text-center white\"><span class=\"fa fa-map-marker fa-1x\"></span> &nbsp; 41 Peabody Street,<br>Nashville, TN</p></li></ul></div></div><div class=\"row margin-20\"><div class=\"col-md-2 col-md-offset-5\"><button type=submit id=button-white class=\"btn-white-animate btn-text-white btn-block\">Submit</button></div></div></div><!-- /.container --></section><!-- /.intro-header --><!-- /Contact Section --><footer class=footer><div class=container><p>Spotwise &copy; 2014</p></div></footer>"
  );


  $templateCache.put('app/message/message.html',
    "<header id=header class=header><div class=container><div class=row><div class=\"col-md-8 col-md-offset-2\" ng-repeat=\"message in awesomeMessages\"><h2 class=text-center>{{ message.name }}</h2><button type=button class=close ng-click=deleteMessage(message)>&times;</button></div></div><div class=row><div class=\"col-md-6 col-md-offset-3\"><form id=contact-form data-parsley-validate><p class=text-center>Get ur messages hre bitches</p><p class=input-group><label for=fullname>Full Name * :</label><input id=fullname name=name required ng-model=\"newMessage.fullname\"><label for=email>Email * :</label><input type=email id=email name=email data-parsley-trigger=change required ng-model=\"newMessage.email\"><label for=message>Message (2 chars min, 100 max) :</label><textarea id=message name=message data-parsley-trigger=keyup data-parsley-minlength=2 data-parsley-maxlength=100 data-parsley-validation-threshold=10 data-parsley-minlength-message=\"Come on! You need to enter at least a 20 caracters long comment..\" ng-model=newMessage.message></textarea><span class=input-group-btn><button type=submit class=\"btn btn-primary\" ng-click=addMessage()>Add New</button></span></p></form></div></div></div></header>"
  );


  $templateCache.put('components/modal/modal.html',
    "<div class=modal-header><button ng-if=modal.dismissable type=button ng-click=$dismiss() class=close>&times;</button><h4 ng-if=modal.title ng-bind=modal.title class=modal-title></h4></div><div class=modal-body><p ng-if=modal.text ng-bind=modal.text></p><div ng-if=modal.html ng-bind-html=modal.html></div></div><div class=modal-footer><button ng-repeat=\"button in modal.buttons\" ng-class=button.classes ng-click=button.click($event) ng-bind=button.text class=btn></button></div>"
  );


  $templateCache.put('components/navbar/navbar.html',
    "<div id=topnav class=\"navbar navbar-default navbar-fixed-top\" ng-controller=NavbarCtrl><div class=container><div class=navbar-header><button class=navbar-toggle type=button ng-click=\"isCollapsed = !isCollapsed\"><span class=sr-only>Toggle navigation</span> <span class=icon-bar></span> <span class=icon-bar></span> <span class=icon-bar></span></button> <a href=\"/\" class=\"navbar-brand logo\"></a></div><div collapse=isCollapsed class=\"navbar-collapse collapse\" id=navbar-main><ul class=\"nav navbar-nav\"><li ng-repeat=\"item in menu\" ng-class=\"{active: isActive(item.link)}\"><a ng-href={{item.link}}>{{item.title}}</a></li><li ng-show=isAdmin() ng-class=\"{active: isActive('/admin')}\"><a href=/admin>Admin</a></li></ul><ul class=\"hidden nav navbar-nav navbar-right\"><li ng-hide=isLoggedIn() ng-class=\"{active: isActive('/signup')}\"><a href=/signup>Sign up</a></li><li ng-hide=isLoggedIn() ng-class=\"{active: isActive('/login')}\"><a href=/login>Login</a></li><li ng-show=isLoggedIn()><p class=navbar-text>Hello {{ getCurrentUser().name }}</p></li><li ng-show=isLoggedIn() ng-class=\"{active: isActive('/settings')}\"><a href=/settings><span class=\"glyphicon glyphicon-cog\"></span></a></li><li ng-show=isLoggedIn() ng-class=\"{active: isActive('/logout')}\"><a href=\"\" ng-click=logout()>Logout</a></li></ul></div></div></div>"
  );

}]);

