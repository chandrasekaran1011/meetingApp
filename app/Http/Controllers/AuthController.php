<?php

namespace App\Http\Controllers;

use Auth;

use Illuminate\Http\Request;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;

use Illuminate\Foundation\Auth\AuthenticatesUsers;

class AuthController extends Controller
{
    use AuthenticatesUsers;
    protected $maxLoginAttempts=3;
    protected $lockoutTime=300;


    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

   /**
    * Get a JWT via given credentials.
    *
    * @return \Illuminate\Http\JsonResponse
    */
   public function login(Request $request)
   {


        $credentials = request(['email', 'password']);

        $credentials = $request->only('email', 'password');

        $this->validate($request, [
        'email' => 'required',
        'password' => 'required',
        ]);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            return response()->json(['error' => 'Too many logins'], 400);
        }

        try{
            if (! $token = auth('api')->attempt($credentials)) {
                $this->incrementLoginAttempts($request);
                return response()->json(['error' => 'Unauthorized'], 401);
            }

        }

        catch (JWTException $e){

            return response()->json(['error' => 'Could Not Create Token'], 500);
        }

        event(new Login('api',auth('api')->user(),true));
        return $this->respondWithToken($token);
   }

   /**
    * Get the authenticated User.
    *
    * @return \Illuminate\Http\JsonResponse
    */
   public function me()
   {
       return response()->json(auth('api')->user());
   }

   /**
    * Log the user out (Invalidate the token).
    *
    * @return \Illuminate\Http\JsonResponse
    */
   public function logout()
   {
       auth('api')->logout();

       event(new Logout('api',auth('api')->user(),true));

       return response()->json(['message' => 'Successfully logged out']);
   }

   /**
    * Refresh a token.
    *
    * @return \Illuminate\Http\JsonResponse
    */
   public function refresh()
   {
       return $this->respondWithToken(auth()->refresh());
   }

   public function guard()
   {
       return Auth::guard('api');
   }

   /**
    * Get the token array structure.
    *
    * @param  string $token
    *
    * @return \Illuminate\Http\JsonResponse
    */
   protected function respondWithToken($token)
   {
       return response()->json([
           'access_token' => $token,
           'token_type' => 'bearer',
           'expires_in' => auth('api')->factory()->getTTL() * 60
       ]);
   }
}
