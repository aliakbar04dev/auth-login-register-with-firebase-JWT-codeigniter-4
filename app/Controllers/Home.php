<?php namespace App\Controllers;

	// panggil JWT
	use \Firebase\JWT\JWT;

	// panggil class Auth
	use App\Controllers\Auth;

	// panggil restful api codeigniter 4
	use CodeIgniter\RESTful\ResourceController;

	// header
	header("Access-Control-Allow-Origin: * ");
	header("Content-Type: application/json; charset=UTF-8");
	header("Access-Control-Allow-Methods: POST");
	header("Access-Control-Max-Age: 3600");
	header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

	class Home extends ResourceController
	{
		public function __construct(){
			// inisialisasi class Auth dengan $this->protect
			$this->protect = new Auth();
		}


		public function index(){
			// ambil secret key dari controller auth
			$secret_key = $this->protect->privateKey();
			$token = null;
			$authHeader = $this->request->getServer('HTTP_AUTHORIZATION');
			$arr = explode(" ", $authHeader);
			$token = $arr[1];

			// jika ada token
			if($token){
				try {
					$decoded = JWT::decode($token, $secret_key, array('HS256'));

					// jika telah di deskripsikan
					if($decoded){

						// halaman akses yang diberikan. Contoh CRUD untuk mengelola database
						$output = [
							'message' => 'Access Granted/Akses Diberikan'
						];
						return $this->respond($output, 200);
					}			 
				} catch (\Exception $e){

					// kalau token salah/expired
					$output = [
						'message' => 'Access denied/Akses Ditolak',
						"error" => $e->getMessage()
					];
					return $this->respond($output, 401);
				}
			}
		}

	}
