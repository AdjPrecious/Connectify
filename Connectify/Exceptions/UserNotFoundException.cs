namespace Connectify.Exceptions
{
    public class UserNotFoundException : NotFoundException
    {
        public UserNotFoundException(string name) : base($"The user with username or email {name} doesn't exist in the database")
        {
        }
    }
}
