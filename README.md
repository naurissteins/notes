# Audio convert

### enc.pl
```
my ($width,$height) = ($vdata->{ID_VIDEO_WIDTH},$vdata->{ID_VIDEO_HEIGHT});
to
my ($width,$height) = ($vdata->{ID_AUDIO_CODEC},$vdata->{ID_AUDIO_CODEC});
``` 
 
```
$ffmpeg_string="$input_str $audio_str $video_str $flags -threads 0 $file_enc";
to
$ffmpeg_string="$input_str $audio_file -threads 0 $file_enc";
```

```
my $file_enc = "$c->{cgi_dir}/temp/$disk_id/$code\_$type.mp4";
to
my $file_enc = "$c->{cgi_dir}/temp/$disk_id/$code\_$type.mp3";
```

```
add new line after
my $video_str = "-c:v libx264 -preset $settings->{vid_preset} $fps_limit $enc_mode $videofilters";
my $audio_file = "-acodec libmp3lame -ac 2 -ab 96k -map a -map_metadata 0:s:0";
```

add after my $input_srt
```
   my $dx = sprintf("%05d",$real_id/$c->{files_per_folder});
   my $idir = "$c->{htdocs_dir}/i/$disk_id/$dx";
   mkdir($idir,0777) unless -d $idir;

   my $filter_w1 = "aformat=channel_layouts=mono,compand=gain=-6,showwavespic=s=800x40:colors=#5593e4"; 
   my $filter_w2 = "aformat=channel_layouts=mono,compand=gain=-6,showwavespic=s=800x40:colors=#8c8c8c";
   my $filter_sc = "showspectrumpic=s=640x512:scale=log:color=rainbow"; 
   my $output_w1 = "$idir/$code\_w1.png";
   my $output_w2 = "$idir/$code\_w2.png";
   my $output_w3 = "$idir/$code\_sp.png";
   my $wave1 = "$c->{ffmpeg} -i $file -filter_complex \"$filter_w1\" -update true $output_w1";
   my $wave2 = "$c->{ffmpeg} -i $file -filter_complex \"$filter_w2\" -update true $output_w2";
   my $spect = "$c->{ffmpeg} -i $file -lavfi \"$filter_sc\" -update true $output_w3";

   system($wave1);
   print"Wave1: $wave1\n";

   system($wave2);
   print"Wave2: $wave1\n"; 

   system($spect);
   print"Spectogram: $spect\n";
```

### fs.pm

```
$keep_orig=0 if $info_orig->{vid_height} <= $info_best->{vid_height};
to
$keep_orig=0 if $file->{file_spec_o}=~ /\.(mp3|flac|wav|acc|m4a|Audio)$/i;
```
