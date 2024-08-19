using AutoMapper;
using Connectify.DataTransferObject;
using Microsoft.AspNetCore.Identity;

namespace Connectify
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<UserForRegistrationDto, IdentityUser>();
        }
    }
}
