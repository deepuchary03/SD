import React, { useState } from 'react';
import { Upload, Music, Image } from 'lucide-react';

interface AdminPanelProps {
  token: string;
}

function AdminPanel({ token }: AdminPanelProps) {
  const [title, setTitle] = useState('');
  const [artist, setArtist] = useState('');
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [imagePreview, setImagePreview] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!audioFile) {
      setError('Please select an audio file');
      return;
    }

    try {
      const formData = new FormData();
      formData.append('title', title);
      formData.append('artist', artist);
      formData.append('audio', audioFile);
      if (imageFile) {
        formData.append('image', imageFile);
      }

      const response = await fetch('http://localhost:3000/api/songs', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to upload song');
      }

      const data = await response.json();
      setSuccess('Song uploaded successfully!');
      setTitle('');
      setArtist('');
      setAudioFile(null);
      setImageFile(null);
      setImagePreview(null);
      setError('');

      // Reset file inputs
      const audioInput = document.getElementById('audio') as HTMLInputElement;
      const imageInput = document.getElementById('image') as HTMLInputElement;
      if (audioInput) audioInput.value = '';
      if (imageInput) imageInput.value = '';
    } catch (err: any) {
      setError(err.message || 'Failed to upload song');
      setSuccess('');
    }
  };

  const handleAudioChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.type.startsWith('audio/')) {
        setError('Please select a valid audio file');
        setAudioFile(null);
        e.target.value = '';
        return;
      }
      setAudioFile(selectedFile);
      setError('');
    }
  };

  const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.type.startsWith('image/')) {
        setError('Please select a valid image file');
        setImageFile(null);
        setImagePreview(null);
        e.target.value = '';
        return;
      }
      setImageFile(selectedFile);
      setError('');
      
      // Create image preview
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result as string);
      };
      reader.readAsDataURL(selectedFile);
    }
  };

  return (
    <div className="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-md">
      <div className="flex items-center space-x-2 mb-6">
        <Upload className="w-6 h-6 text-blue-500" />
        <h2 className="text-2xl font-bold">Upload Music</h2>
      </div>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
          {success}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">
            Song Title
          </label>
          <input
            type="text"
            id="title"
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-200"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
          />
        </div>

        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="artist">
            Artist
          </label>
          <input
            type="text"
            id="artist"
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-200"
            value={artist}
            onChange={(e) => setArtist(e.target.value)}
            required
          />
        </div>

        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="audio">
            Audio File
          </label>
          <div className="flex items-center justify-center w-full">
            <label className="w-full flex flex-col items-center px-4 py-6 bg-white rounded-lg shadow-lg tracking-wide border border-blue-500 cursor-pointer hover:bg-blue-500 hover:text-white">
              <Music className="w-8 h-8" />
              <span className="mt-2 text-base">
                {audioFile ? audioFile.name : 'Select audio file'}
              </span>
              <input
                type="file"
                id="audio"
                className="hidden"
                accept="audio/*"
                onChange={handleAudioChange}
                required
              />
            </label>
          </div>
        </div>

        <div className="mb-6">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="image">
            Cover Image (Optional)
          </label>
          <div className="flex items-center justify-center w-full">
            <label className="w-full flex flex-col items-center px-4 py-6 bg-white rounded-lg shadow-lg tracking-wide border border-blue-500 cursor-pointer hover:bg-blue-500 hover:text-white">
              <Image className="w-8 h-8" />
              <span className="mt-2 text-base">
                {imageFile ? imageFile.name : 'Select cover image'}
              </span>
              <input
                type="file"
                id="image"
                className="hidden"
                accept="image/*"
                onChange={handleImageChange}
              />
            </label>
          </div>
          {imagePreview && (
            <div className="mt-4">
              <img
                src={imagePreview}
                alt="Cover preview"
                className="w-32 h-32 object-cover rounded-lg"
              />
            </div>
          )}
        </div>

        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50"
        >
          Upload Song
        </button>
      </form>
    </div>
  );
}

export default AdminPanel;