package com.kh.menu.security.model.service;
import java.util.List;
import java.util.Map;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kh.menu.security.model.dao.AuthDao;
import com.kh.menu.security.model.dto.AuthDto.AuthResult;
import com.kh.menu.security.model.dto.AuthDto.User;
import com.kh.menu.security.model.dto.AuthDto.UserAuthority;
import com.kh.menu.security.model.dto.AuthDto.UserCredential;
import com.kh.menu.security.model.provider.JWTProvider;
import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class AuthService {
//    private final CorsConfigurationSource corsConfigurationSource;
//    private final MenuApplication menuApplication;
	private final AuthDao authDao;
	private final PasswordEncoder encoder; // Bean 객체 생성 필요
	private final KakaoService service; // Bean 객체 생성 필요
	private final JWTProvider jwt;
	
	public boolean existsByEmail(String email) {
		User user = authDao.findUserByEmail(email);
		return user != null; // user가 존재할 시 true
	}
	public AuthResult login(String email, String password) {
		// 1. 사용자 정보 조회
		User user = authDao.findUserByEmail(email);
		
		if(!encoder.matches(password, user.getPassword())) { // encoder.matches(평문 패스워드, 인코딩 된 패스워드)
			throw new BadCredentialsException("비밀번호 오류");
		}
		
		// 2. 토큰 발급
		String acessToken = jwt.createAccessToken(user.getId(), 30); // 30분 유효
		String refreshToken = jwt.createRefreshToken(user.getId(), 7);
		
		User userNoPassword = User.builder()
				.id(user.getId())
				.email(user.getEmail())
				.name(user.getName())
				.profile(user.getProfile())
				.roles(user.getRoles())
				.build();
		
		return AuthResult.builder()
				.accessToken(acessToken)
				.refreshToken(refreshToken)
				.user(userNoPassword)
				.build();
	}
	@Transactional
	public AuthResult signup(String email, String password) {
		// 1) Users 테이블에 데이터 추가
		User user = User.builder()
						.email(email)
						.name(email.split("@")[0])
						.build();
		authDao.insertUser(user);
		
		// 2) Credential 추가
		UserCredential cred = UserCredential.builder()
								.userId(user.getId())
								.password(encoder.encode(password))
								.build();
		
		authDao.insertCred(cred);
		// 3) 기본 권한 추가
		UserAuthority auth = UserAuthority.builder()
								.userId(user.getId())
								.roles(List.of("ROLE_USER"))
								.build();
		authDao.insertUserRole(auth);
		
		// 4) 토큰 발급
		String accessToken = jwt.createAccessToken(user.getId(), 30); // 30분
		String refreshToken = jwt.createRefreshToken(user.getId(), 7); // 7일
		
		user = authDao.findUserByUserId(user.getId()); // 비밀번호 제외 필요 ================================
		
		return AuthResult.builder()
				.accessToken(accessToken)
				.refreshToken(refreshToken)
				.user(user)
				.build();
	}
	public AuthResult refreshByCookie(String refreshCookie) {
		Long userId = jwt.parseRefresh(refreshCookie);
		User user = authDao.findUserByUserId(userId);
		
		String accessToken = jwt.createAccessToken(userId, 30);
		
		// 비밀번호 제거 과정
		return AuthResult.builder()
				.accessToken(accessToken)
				.user(user)
				.build();
	}
	public User findUserByUserId(Long userId) {
		String accessToken = authDao.getKakaoAccessToken(userId);
		Map<String, Object> userInfo = service.getUserInfo(accessToken);
		
		Map<String, Object> kakaoAccount = (Map<String, Object>)userInfo.get("kakao_account");
		Map<String, Object> profile2 = (Map<String, Object>)kakaoAccount.get("profile");
		
		String nickname = (String)(profile2.get("nickname"));
		String profile = (String)(profile2.get("profile_image_url"));
		String email = (String)(kakaoAccount.get("email"));
		
		User user = User.builder()
				.name(nickname)
				.email(email)
				.profile(profile)
				.roles(List.of("ROLE_USER"))
				.build();
		
		return user;
	}
	public String getKakaoAccessToken(Long userId) {
		return authDao.getKakaoAccessToken(userId);
	}
}