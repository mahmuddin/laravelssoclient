<?php

namespace App\Http\Controllers\SSO;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class SSOController extends Controller
{
    public function getLogin(Request $request)
    {
        $state = Str::random(40);
        $request->session()->put("state", $state);
        $query = http_build_query([
            "client_id" => "98baf03e-8116-439a-9621-5b6ee91b670b",
            "redirect_uri" => "http://127.0.0.1:8080/callback",
            "response_type" => "code",
            "scope" => "view-user",
            "state" => $state
        ]);
        return redirect("http://127.0.0.1:8000/oauth/authorize?" . $query);
    }

    public function getCallback(Request $request)
    {
        $state = $request->session()->pull("state");

        throw_unless(strlen($state) > 0 && $state == $request->state, InvalidArgumentException::class);

        $response = Http::asForm()->post(
            "http://127.0.0.1:8000/oauth/token",
            [
                "grant_type" => "authorization_code",
                "client_id" => "98baf03e-8116-439a-9621-5b6ee91b670b",
                "client_secret" => "xYxj4NPlJeckAEuDeUNxqBESP7gdPRF8J9W4zU3M",
                "redirect_uri" => "http://127.0.0.1:8080/callback",
                "code" => $request->code
            ]
        );
        $request->session()->put($response->json());
        return redirect(route("sso.connect"));
    }

    public function connectUser(Request $request)
    {
        $access_token = $request->session()->get("access_token");

        $response = Http::withHeaders([
            "Accept" => "application/json",
            "Authorization" => "Bearer " . $access_token
        ])->get("http://127.0.0.1:8000/api/user");
        $userArray = $response->json();

        try {
            $email = $userArray['email'];
        } catch (\Throwable $th) {
            return redirect("login")->withError("Failed to get login information! Try again.");
        }
        $user = User::where("email", $email)->first();
        if (!$user) {
            $user = new User;
            $user->name = $userArray['name'];
            $user->email = $userArray['email'];
            $user->email_verified_at = $userArray['email_verified_at'];
            $user->save();
        }
        Auth::login($user);
        return redirect(route("home"));
    }
}
