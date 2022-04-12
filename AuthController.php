<?php

namespace App\Http\Controllers\API;

use Illuminate\Support\Facades\Validator;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'fullname' => 'required|max:191',
            'email' => 'required|email|max:191|unique:users,email',
            'password' => 'required|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'validation_errors' => $validator->messages(),
            ]);
        } else {
            $user = User::create([
                'name'=>$request->fullname,
                'email'=>$request->email,
                'password'=>Hash::make($request->password),
            ]);

            $token = $user->createToken($user->email.'_Token')->plainTextToken;
            
            return response()->json([
                'status' => 200,
                'fullname' => $user->name,
                'token' => $token,
                'message' => 'Registracija Sėkmingai',
            ]);
        }
    }

    public function login(Request $request) {
        $messages = [
            "email.required" => "El. Paštas yra privalomas",
            "email.email" => "El. Paštas neatpažintas",
            "email.exists" => "El. Paštas neegzistuoja",
            "password.required" => "Slaptažodis yra privalomas",
            "password.min" => "Slaptažodis per trumpas (>6)"
        ];
        
        // validate the form data
        $validator = Validator::make($request->all(), [
                'email' => 'required|email|exists:users,email',
                'password' => 'required|min:6'
        ], $messages);

        if ($validator->fails()) {
            return response()->json([
                'validation_errors' => $validator->messages(),
            ]);
        } else {
            $user = User::where('email', $request->email)->first();
 
            if (!$user || ! Hash::check($request->password, $user->password)) {
                return response()->json([
                    'status' => '401',
                    'message' => 'Neteisingi Įgaliojimai',
                    'validation_errors' => $validator->messages()->add('fields.missmatch', 'Neteisingi Įgaliojimai'),
                ]);

            }
            else {
                $token = $user->createToken($user->email.'_Token')->plainTextToken;
            
                return response()->json([
                    'status' => 200,
                    'fullname' => $user->name,
                    'token' => $token,
                    'message' => 'Prisijungėte Sėkmingai',
                ]);
            }
        }
    }

    public function logout() {
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => 200,
            'message' => 'Atsijungėte Sėkmingai!'
        ]);
    }
}
