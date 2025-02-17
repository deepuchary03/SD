import React, { useState, useEffect, useRef } from "react";
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Volume2,
  Heart,
  Search,
  X,
} from "lucide-react";

interface Song {
  _id: string;
  title: string;
  artist: string;
  audioUrl: string;
  imageUrl: string;
  likes: number;
  isLiked: boolean;
}

interface MusicPlayerProps {
  token: string;
}

function MusicPlayer({ token }: MusicPlayerProps) {
  const [songs, setSongs] = useState<Song[]>([]);
  const [currentSongIndex, setCurrentSongIndex] = useState<number | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [volume, setVolume] = useState(0.5);
  const [searchQuery, setSearchQuery] = useState("");
  const audioRef = useRef<HTMLAudioElement>(null);
  const [error, setError] = useState("");
  const [isSearching, setIsSearching] = useState(false);

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchSongs();
    }, 300);

    return () => clearTimeout(delayDebounceFn);
  }, [searchQuery]);

  const fetchSongs = async () => {
    try {
      setIsSearching(true);
      const url = searchQuery
        ? `https://sd-6ykp.onrender.com/api/songs?search=${encodeURIComponent(
            searchQuery
          )}`
        : "https://sd-6ykp.onrender.com/api/songs";

      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch songs");
      }

      const data = await response.json();
      setSongs(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsSearching(false);
    }
  };

  const togglePlay = () => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause();
      } else {
        audioRef.current.play();
      }
      setIsPlaying(!isPlaying);
    }
  };

  const playPrevious = () => {
    if (currentSongIndex !== null) {
      setCurrentSongIndex((prevIndex) =>
        prevIndex === 0 ? songs.length - 1 : prevIndex - 1
      );
    }
  };

  const playNext = () => {
    if (currentSongIndex !== null) {
      setCurrentSongIndex((prevIndex) =>
        prevIndex === songs.length - 1 ? 0 : prevIndex + 1
      );
    }
  };

  const handleVolumeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newVolume = parseFloat(e.target.value);
    setVolume(newVolume);
    if (audioRef.current) {
      audioRef.current.volume = newVolume;
    }
  };

  const handleLike = async (songId: string) => {
    try {
      const response = await fetch(
        `https://sd-6ykp.onrender.com/api/songs/${songId}/like`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        throw new Error("Failed to update like status");
      }

      const { likes, isLiked } = await response.json();
      setSongs((prevSongs) =>
        prevSongs.map((song) =>
          song._id === songId ? { ...song, likes, isLiked } : song
        )
      );
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="container mx-auto px-4 bg-gradient-to-b from-rose-50 to-pink-50 min-h-screen pb-24">
      {/* Search Bar - Always visible */}
      <div className="sticky top-0 z-10 bg-white/80 backdrop-blur-md py-4 px-4 mb-8">
        <div className="max-w-xl mx-auto">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-rose-400" />
            </div>
            <input
              type="text"
              placeholder="Search songs..."
              className="pl-10 block w-full rounded-xl border-rose-200 shadow-sm focus:border-rose-300 focus:ring focus:ring-rose-200 focus:ring-opacity-50 bg-white/90"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      {isSearching ? (
        <div className="text-center py-8">
          <p className="text-rose-600">Searching...</p>
        </div>
      ) : songs.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-rose-600">
            No songs found. Try a different search or add some music.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6 mb-8">
          {songs.map((song, index) => (
            <div
              key={song._id}
              className="bg-white/90 rounded-xl shadow-lg overflow-hidden hover:shadow-xl transition-all duration-300 transform hover:-translate-y-1"
            >
              <div className="relative group">
                <img
                  src={song.imageUrl}
                  alt={`${song.title} cover`}
                  className="w-full aspect-square object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-rose-500/60 to-pink-500/60 opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-center justify-center">
                  <button
                    onClick={() => {
                      setCurrentSongIndex(index);
                      setIsPlaying(true);
                      if (audioRef.current) {
                        audioRef.current.play();
                      }
                    }}
                    className="bg-white text-rose-500 rounded-full p-4 transform hover:scale-110 transition-transform duration-300 shadow-lg"
                  >
                    <Play className="w-8 h-8" />
                  </button>
                </div>
              </div>
              <div className="p-4">
                <h3 className="font-semibold text-lg mb-1 truncate text-rose-900">
                  {song.title}
                </h3>
                <p className="text-rose-600 text-sm mb-2 truncate">
                  {song.artist}
                </p>
                <div className="flex items-center justify-between">
                  <button
                    onClick={() => handleLike(song._id)}
                    className="flex items-center space-x-1"
                  >
                    <Heart
                      className={`w-5 h-5 ${
                        song.isLiked
                          ? "fill-rose-500 text-rose-500"
                          : "text-rose-300"
                      }`}
                    />
                    <span className="text-sm text-rose-600">{song.likes}</span>
                  </button>
                  {currentSongIndex === index && isPlaying && (
                    <div className="text-rose-500 text-sm">Now Playing</div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Player Bar */}
      {currentSongIndex !== null && (
        <div className="fixed bottom-0 left-0 right-0 bg-white/95 backdrop-blur-md border-t border-rose-200 shadow-lg p-4">
          <div className="max-w-7xl mx-auto flex items-center justify-between">
            <div className="flex items-center space-x-4 flex-1">
              <img
                src={songs[currentSongIndex].imageUrl}
                alt={`${songs[currentSongIndex].title} cover`}
                className="w-16 h-16 rounded-lg object-cover shadow-md"
              />
              <div>
                <h3 className="font-semibold text-rose-900">
                  {songs[currentSongIndex].title}
                </h3>
                <p className="text-rose-600 text-sm">
                  {songs[currentSongIndex].artist}
                </p>
              </div>
            </div>

            <audio
              ref={audioRef}
              src={songs[currentSongIndex].audioUrl}
              onEnded={playNext}
              onPlay={() => setIsPlaying(true)}
              onPause={() => setIsPlaying(false)}
            />

            <div className="flex items-center space-x-4 flex-1 justify-center">
              <button
                onClick={playPrevious}
                className="p-2 rounded-full hover:bg-rose-50"
              >
                <SkipBack className="w-6 h-6 text-rose-600" />
              </button>

              <button
                onClick={togglePlay}
                className="p-3 rounded-full bg-gradient-to-r from-rose-500 to-pink-500 hover:from-rose-600 hover:to-pink-600 text-white shadow-lg transform hover:scale-105 transition-all duration-300"
              >
                {isPlaying ? (
                  <Pause className="w-6 h-6" />
                ) : (
                  <Play className="w-6 h-6" />
                )}
              </button>

              <button
                onClick={playNext}
                className="p-2 rounded-full hover:bg-rose-50"
              >
                <SkipForward className="w-6 h-6 text-rose-600" />
              </button>
            </div>

            <div className="flex items-center space-x-4 flex-1 justify-end">
              <div className="flex items-center space-x-2">
                <Volume2 className="w-5 h-5 text-rose-600" />
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.01"
                  value={volume}
                  onChange={handleVolumeChange}
                  className="w-24 h-2 bg-rose-200 rounded-lg appearance-none cursor-pointer"
                />
              </div>
              <button
                onClick={() => setCurrentSongIndex(null)}
                className="p-2 rounded-full hover:bg-rose-50"
              >
                <X className="w-5 h-5 text-rose-600" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default MusicPlayer;
