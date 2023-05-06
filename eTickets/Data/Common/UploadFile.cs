using Azure.Storage.Blobs;

namespace eTickets.Data.Common
{
    public class UploadFile
    {
        private string connectionString = "DefaultEndpointsProtocol=https;AccountName=noobdevdotnet;AccountKey=49bYgg/hYCI+t7+fEf7LjWxIGlnZrFr3stMFKHvASGgWPtE2VHs5l4kMI3LJS790rpuhN14EDAg7+AStDGnGGA==;EndpointSuffix=core.windows.net";
        private string containerName = "images";
        public string SaveFile(IFormFile file)
        {
            var filename = file.FileName;
            var fileURL = "";
            BlobContainerClient container = new BlobContainerClient(connectionString, containerName);
            try
            {
                BlobClient blob = container.GetBlobClient(filename);
                using (Stream stream = file.OpenReadStream())
                {
                    blob.Upload(stream);
                }
                fileURL = blob.Uri.AbsoluteUri;
                return fileURL;
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
