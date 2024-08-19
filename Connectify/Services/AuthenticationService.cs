using AutoMapper;
using Connectify.DataTransferObject;
using Microsoft.AspNetCore.Identity;

namespace Connectify.Services
{
    public class AuthenticationService : IAuthenticationService 
    {
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
       

        public AuthenticationService(IMapper mapper, UserManager<IdentityUser> userManager)
        {
            _mapper = mapper;
            _userManager = userManager;
            
        }

        public async Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistrationDto)
        {
            var user = _mapper.Map<IdentityUser>(userForRegistrationDto);

            var result = await _userManager.CreateAsync(user, userForRegistrationDto.Password);

            return result;
        }
    }
}
