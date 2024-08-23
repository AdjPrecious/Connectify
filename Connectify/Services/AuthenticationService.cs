using AutoMapper;
using Connectify.DataTransferObject;
using Connectify.Logger;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Connectify.Services
{
    public class AuthenticationService : IAuthenticationService 
    {
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILoggerManager _logger;
        private readonly IConfiguration _configuration;
        private IdentityUser? _identityUser;
       

        public AuthenticationService(IMapper mapper, UserManager<IdentityUser> userManager, ILoggerManager logger, IConfiguration configuration)
        {
            _mapper = mapper;
            _userManager = userManager;
            _logger = logger;
            _configuration = configuration;
        }

        public string CreateToken()
        {
            var signingCredentials = GetSigningCredentials();
            var claims =  GetClaimsByUserName();

            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

       

        public async Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistrationDto)
        {
            var user = _mapper.Map<IdentityUser>(userForRegistrationDto);

            var result = await _userManager.CreateAsync(user, userForRegistrationDto.Password);

            return result;
        }

        public async Task<bool> ValidateUser(UserForAuthentication userForAuth)
        {
            _identityUser = await _userManager.FindByNameAsync(userForAuth.UserName);

            if (_identityUser == null)
                _identityUser = await _userManager.FindByEmailAsync(userForAuth.UserName);

            var result = (_identityUser != null && await _userManager.CheckPasswordAsync(_identityUser, userForAuth.Password));

            if (!result)
                _logger.LogWarn($"{nameof(ValidateUser)}: Authentication failed. Wrong user name or password. ");
            return result;
        }

        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"));

            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private List<Claim> GetClaimsByUserName()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, _identityUser.UserName)
            };
           

            return claims;
        }

       

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSetting");

            var tokenOptions = new JwtSecurityToken(
                issuer: jwtSettings["validIssuer"],
                audience: jwtSettings["validAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["expires"])),
                signingCredentials: signingCredentials
                );
                return tokenOptions;
                
                
        }


    }
}
