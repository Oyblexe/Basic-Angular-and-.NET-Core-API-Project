using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace JwtAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtSettings _jwtSettings;

        // Kullanıcı bilgilerini saklamak için basit bir in-memory liste (gerçek uygulamada veritabanı kullanmalısınız)
        private static readonly List<User> Users = new List<User>
        {
            // Varsayılan kullanıcı (örnek: admin/admin)
            new User { Username = "admin", Password = "admin", Email = "admin@example.com" }
        };

        public AuthController(IConfiguration configuration)
        {
            _jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] UserLogin user)
        {
            // Kullanıcı doğrulama
            var existingUser = Users.FirstOrDefault(u => u.Username == user.Username && u.Password == user.Password);
            if (existingUser != null)
            {
                try
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.Name, existingUser.Username),
                            new Claim(ClaimTypes.Role, "User") // Kullanıcı rolü örnek olarak
                        }),
                        Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                        Issuer = _jwtSettings.Issuer,
                        Audience = _jwtSettings.Audience,
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };

                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var tokenString = tokenHandler.WriteToken(token);

                    return Ok(new { Token = tokenString });
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return StatusCode(500, new { Message = "Bir hata oluştu. Lütfen daha sonra tekrar deneyin." });
                }
            }

            return Unauthorized(new { Message = "Kullanıcı adı veya şifre hatalı." });
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] UserRegister newUser)
        {
            // Kullanıcı adı veya e-posta ile zaten kayıtlı bir kullanıcı olup olmadığını kontrol edin
            var existingUser = Users.FirstOrDefault(u => u.Username == newUser.Username || u.Email == newUser.Email);
            if (existingUser != null)
            {
                return BadRequest(new { Message = "Bu kullanıcı adı veya e-posta zaten kullanılıyor." });
            }

            // Yeni kullanıcıyı in-memory listeye ekleyin
            Users.Add(new User
            {
                Username = newUser.Username,
                Email = newUser.Email,
                Password = newUser.Password // Şifreleri hash'leyip saklamanız tavsiye edilir
            });

            return Ok(new { Message = "Kullanıcı kaydı başarılı" });
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {
            if (resetPasswordModel == null || string.IsNullOrEmpty(resetPasswordModel.Email))
            {
                return BadRequest(new { Message = "Geçersiz istek. E-posta adresi gerekli." });
            }

            // Kullanıcının varlığını kontrol et
            var user = Users.FirstOrDefault(u => u.Email == resetPasswordModel.Email);
            if (user == null)
            {
                return BadRequest(new { Message = "Parola sıfırlama başarısız, e-posta bulunamadı" });
            }

            // Parola sıfırlama işlemini simüle et
            // Gerçek bir uygulamada, yeni bir şifre oluşturulmalı ve kullanıcının e-postasına gönderilmeli
            user.Password = "newpassword"; // Örnek olarak yeni parola ataması

            return Ok(new { Message = "Parola sıfırlama başarılı, yeni parolanız email ile gönderildi" });
        }
    }

    // Kullanıcı giriş modelini temsil eder
    public class UserLogin
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    // Kullanıcı kayıt modelini temsil eder
    public class UserRegister
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    // Parola sıfırlama modelini temsil eder
    public class ResetPasswordModel
    {
        public string Email { get; set; } = string.Empty;
    }

    // JWT ayarlarını temsil eden sınıf
    public class JwtSettings
    {
        public string SecretKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpirationInMinutes { get; set; }
    }

    // Basit bir kullanıcı modelini temsil eder
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }
}
