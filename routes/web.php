<?php

use App\Http\Controllers\SSO\SSOController;
use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get("/sso/login", [SSOController::class, 'getLogin'])->name("sso.login");
Route::get("/callback", [SSOController::class, 'getCallback'])->name("sso.callback");
Route::get("/sso/connect", [SSOController::class, 'connectUser'])->name("sso.connect");

Auth::routes(["register" => false, "reset" => false]);

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');
Route::get('/', [App\Http\Controllers\HomeController::class, 'index'])->name('index');
