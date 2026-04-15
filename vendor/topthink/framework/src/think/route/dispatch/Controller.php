<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006~2025 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------
declare (strict_types = 1);

namespace think\route\dispatch;

use Closure;
use think\App;
use think\exception\ClassNotFoundException;
use think\exception\HttpException;
use think\helper\Str;
use think\route\Dispatch;

/**
 * Controller Dispatcher
 */
class Controller extends Dispatch
{
    /**
     * 模块名
     * @var string
     */
    protected $layer;

    /**
     * 控制器名
     * @var string
     */
    protected $controller;

    /**
     * 操作名
     * @var string
     */
    protected $actionName;

    public function init(App $app)
    {
        $this->app = $app;
        $this->parseDispatch($this->dispatch);
        $this->doRouteAfter();
    }

    protected function parseDispatch($path)
    {
        if (is_string($path)) {
            $path = explode('/', $path);
        }

        $action     = !empty($path) ? array_pop($path) : $this->rule->config('default_action');
        $controller = !empty($path) ? array_pop($path) : $this->rule->config('default_controller');
        $layer      = !empty($path) ? implode('/', $path) : '';

        if ($layer && !empty($this->option['auto_middleware'])) {
            // 自动为顶层layer注册中间件
            $alias = $this->app->config->get('middleware.alias', []);

            if (isset($alias[$layer])) {
                $this->option['middleware'] = array_merge($this->option['middleware'] ?? [], [$layer]);
            }
        }

        $this->actionName = strip_tags($action);
        $this->layer      = strip_tags($layer);
        $this->controller = strip_tags($controller);

        // 设置当前请求的控制器、操作
        $this->request
            ->setLayer($this->layer)
            ->setController($this->controller)
            ->setAction($this->actionName);
    }

    public function exec()
    {
        try {
            // 实例化控制器
            $instance = $this->controller();
            if ($this->miss && !method_exists($instance, $this->actionName . $this->rule->config('action_suffix'))) {
                throw new ClassNotFoundException('class not exists:');
            }
        } catch (ClassNotFoundException $e) {
            if ($this->miss) {
                $route = $this->miss->getRoute();
                if ($route instanceof Closure) {
                    $vars = $this->getActionBindVars();
                    return $this->app->invoke($route, $vars);
                }
                // 检查分组绑定
                $prefix = $this->rule->getOption('prefix');
                if (!str_starts_with($route, $prefix)) {
                    $route = $prefix . $route;
                }
                $this->parseDispatch($route);
                $instance = $this->controller();
            } else {
                throw new HttpException(404, 'controller not exists:' . $e->getClass());
            }
        }

        return $this->responseWithMiddlewarePipeline($instance, $this->actionName);
    }

    /**
     * 实例化访问控制器
     * @access public
     * @return object
     * @throws ClassNotFoundException
     */
    public function controller()
    {
        $suffix          = $this->rule->config('controller_suffix') ? 'Controller' : '';
        $controllerLayer = $this->rule->config('controller_layer') ?: 'controller';
        $emptyController = $this->rule->config('empty_controller') ?: 'Error';

        $class = $this->app->parseClass($controllerLayer, $this->controller . $suffix, $this->layer);
        if (class_exists($class)) {
            return $this->app->make($class, [], true);
        } elseif ($emptyController && class_exists($emptyClass = $this->app->parseClass($controllerLayer, $emptyController . $suffix, $this->layer))) {
            return $this->app->make($emptyClass, [], true);
        }

        throw new ClassNotFoundException('class not exists:' . $class, $class);
    }
}
